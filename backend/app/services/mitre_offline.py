import json
import os
import re
from typing import Dict, Any, List, Optional


class MitreOfflineService:
    """
    Offline MITRE ATT&CK loader + search.
    Reads enterprise-attack.json (STIX bundle) and builds:
    - group index (APT groups)
    - technique index
    - alias matching (OilRig -> APT34)
    """

    def __init__(self):
        self.data_path = os.getenv(
            "MITRE_ENTERPRISE_JSON",
            os.path.join("app", "data", "mitre", "enterprise-attack.json")
        )

        self.loaded = False
        self.raw_objects: List[Dict[str, Any]] = []

        # Indexes
        self.groups_by_id: Dict[str, Dict[str, Any]] = {}
        self.groups_by_name: Dict[str, Dict[str, Any]] = {}
        self.group_alias_map: Dict[str, str] = {}  # alias -> canonical group name

        self.techniques_by_id: Dict[str, Dict[str, Any]] = {}
        self.techniques_by_stix_id: Dict[str, Dict[str, Any]] = {}

        # relationships: group -> techniques
        self.group_to_techniques: Dict[str, List[str]] = {}  # group_stix_id -> list of technique_stix_ids

        # ✅ NEW Indexes for Phase 5
        self.tactics_by_shortname: Dict[str, Dict[str, Any]] = {}  # lateral-movement -> x-mitre-tactic obj
        self.tactics_by_name: Dict[str, Dict[str, Any]] = {}       # "lateral movement" -> obj

        self.technique_name_map: Dict[str, str] = {}  # normalized technique name -> technique_id (Txxxx)
        self.technique_to_tactics: Dict[str, List[str]] = {}  # technique_stix_id -> ["lateral-movement", ...]

        # optional: mitigation index
        self.mitigations_by_stix_id: Dict[str, Dict[str, Any]] = {}
        self.technique_to_mitigations: Dict[str, List[str]] = {}  # technique_stix_id -> mitigation_stix_ids

    def _normalize(self, text: str) -> str:
        return re.sub(r"\s+", " ", str(text).strip().lower())

    def _is_technique_id(self, query: str) -> bool:
        """
        Matches technique IDs like:
        - T1055
        - t1055
        - T1055.001
        """
        if not query:
            return False
        q = query.strip().upper()
        return bool(re.match(r"^T\d{4}(\.\d{3})?$", q))

    def load(self) -> None:
        if self.loaded:
            return

        if not os.path.exists(self.data_path):
            raise FileNotFoundError(
                f"MITRE dataset not found at: {self.data_path}. "
                f"Place enterprise-attack.json inside app/data/mitre/"
            )

        with open(self.data_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        self.raw_objects = bundle.get("objects", [])

        # 1) Load groups (intrusion-set)
        for obj in self.raw_objects:
            if obj.get("type") == "intrusion-set":
                stix_id = obj.get("id")
                name = obj.get("name", "")

                if not stix_id or not name:
                    continue

                norm_name = self._normalize(name)

                self.groups_by_id[stix_id] = obj
                self.groups_by_name[norm_name] = obj

                # aliases
                aliases = obj.get("aliases", []) or []
                for a in aliases:
                    norm_alias = self._normalize(a)
                    if norm_alias and norm_alias not in self.group_alias_map:
                        self.group_alias_map[norm_alias] = norm_name

        # 2) Load techniques (attack-pattern)
        for obj in self.raw_objects:
            if obj.get("type") == "attack-pattern":
                stix_id = obj.get("id")
                name = obj.get("name", "")

                if not stix_id or not name:
                    continue

                # external_id = Txxxx
                external_refs = obj.get("external_references", []) or []
                technique_id = None
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        technique_id = ref.get("external_id")
                        break

                self.techniques_by_stix_id[stix_id] = obj
                if technique_id:
                    self.techniques_by_id[technique_id] = obj

                # ✅ NEW: name -> technique id map (for searching by "Process Injection")
                norm_tname = self._normalize(name)
                if technique_id and norm_tname and norm_tname not in self.technique_name_map:
                    self.technique_name_map[norm_tname] = technique_id

        # ✅ NEW: Load tactics (x-mitre-tactic)
        for obj in self.raw_objects:
            if obj.get("type") == "x-mitre-tactic":
                name = obj.get("name", "")
                shortname = obj.get("x_mitre_shortname", "")

                if name:
                    self.tactics_by_name[self._normalize(name)] = obj

                if shortname:
                    self.tactics_by_shortname[self._normalize(shortname)] = obj

        # 3) Load relationships (intrusion-set uses attack-pattern)
        for obj in self.raw_objects:
            if obj.get("type") == "relationship":
                if obj.get("relationship_type") != "uses":
                    continue

                src = obj.get("source_ref", "")
                tgt = obj.get("target_ref", "")

                # intrusion-set -> attack-pattern
                if src.startswith("intrusion-set--") and tgt.startswith("attack-pattern--"):
                    if src not in self.group_to_techniques:
                        self.group_to_techniques[src] = []
                    self.group_to_techniques[src].append(tgt)

        # ✅ NEW: Load mitigations (course-of-action)
        for obj in self.raw_objects:
            if obj.get("type") == "course-of-action":
                stix_id = obj.get("id")
                if stix_id:
                    self.mitigations_by_stix_id[stix_id] = obj

        # ✅ NEW: Load relationships for mitigations + technique tactics
        for obj in self.raw_objects:
            if obj.get("type") == "relationship":
                rel_type = obj.get("relationship_type")
                src = obj.get("source_ref", "")
                tgt = obj.get("target_ref", "")

                # technique -> mitigation mapping
                # In STIX, mitigation often "mitigates" technique:
                # course-of-action mitigates attack-pattern
                if rel_type == "mitigates":
                    if src.startswith("course-of-action--") and tgt.startswith("attack-pattern--"):
                        if tgt not in self.technique_to_mitigations:
                            self.technique_to_mitigations[tgt] = []
                        self.technique_to_mitigations[tgt].append(src)

        # ✅ NEW: technique -> tactics mapping from kill_chain_phases
        for stix_id, tech_obj in self.techniques_by_stix_id.items():
            phases = tech_obj.get("kill_chain_phases", []) or []
            tactics: List[str] = []
            for p in phases:
                if p.get("kill_chain_name") == "mitre-attack":
                    phase_name = p.get("phase_name")
                    if phase_name:
                        tactics.append(self._normalize(phase_name))
            if tactics:
                self.technique_to_tactics[stix_id] = list(sorted(set(tactics)))

        self.loaded = True

    def find_group(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Search group by:
        - exact group name
        - alias (OilRig -> APT34)
        """
        self.load()

        nq = self._normalize(query)

        # direct group name
        if nq in self.groups_by_name:
            return self.groups_by_name[nq]

        # alias match
        if nq in self.group_alias_map:
            canonical = self.group_alias_map[nq]
            return self.groups_by_name.get(canonical)

        # partial match fallback
        for gname, gobj in self.groups_by_name.items():
            if nq in gname:
                return gobj

        # partial alias match
        for alias, canonical in self.group_alias_map.items():
            if nq in alias:
                return self.groups_by_name.get(canonical)

        return None

    def get_group_techniques(self, group_obj: Dict[str, Any], limit: int = 25) -> List[Dict[str, Any]]:
        """
        Returns list of techniques used by group (basic fields).
        """
        self.load()

        group_id = group_obj.get("id")
        if not group_id:
            return []

        technique_stix_ids = self.group_to_techniques.get(group_id, [])
        results: List[Dict[str, Any]] = []

        for tid in technique_stix_ids[:limit]:
            t = self.techniques_by_stix_id.get(tid)
            if not t:
                continue

            # find technique external_id (Txxxx)
            external_refs = t.get("external_references", []) or []
            technique_id = None
            url = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    url = ref.get("url")
                    break

            results.append({
                "technique_id": technique_id,
                "name": t.get("name"),
                "description": (t.get("description") or "")[:300],
                "url": url
            })

        return results

    def build_mitre_mapping_for_query(self, query: str) -> List[str]:
        """
        Returns MITRE mapping list like:
        ["APT34 (OilRig)", "T1059 Command and Scripting Interpreter", ...]
        """
        self.load()

        group = self.find_group(query)
        if not group:
            return []

        group_name = group.get("name", "Unknown Group")
        aliases = group.get("aliases", []) or []

        alias_text = ""
        if aliases:
            alias_text = f" ({', '.join(aliases[:3])})"

        mapping: List[str] = [f"{group_name}{alias_text}"]

        techniques = self.get_group_techniques(group, limit=15)
        for t in techniques:
            tid = t.get("technique_id")
            tname = t.get("name")
            if tid and tname:
                mapping.append(f"{tid} {tname}")
            elif tname:
                mapping.append(str(tname))

        return mapping

    # ==========================================================
    # ✅ NEW FUNCTIONS FOR PHASE 5
    # ==========================================================

    def find_tactic(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Find MITRE tactic by:
        - Name: "Lateral Movement"
        - Shortname: "lateral-movement"
        """
        self.load()
        nq = self._normalize(query)

        if nq in self.tactics_by_name:
            return self.tactics_by_name[nq]

        if nq in self.tactics_by_shortname:
            return self.tactics_by_shortname[nq]

        # partial match
        for name, obj in self.tactics_by_name.items():
            if nq in name:
                return obj

        for short, obj in self.tactics_by_shortname.items():
            if nq in short:
                return obj

        return None

    def find_technique(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Find technique by:
        - Technique ID: T1055 or T1055.001
        - Technique name: "Process Injection"
        - Partial match
        """
        self.load()
        if not query:
            return None

        q = query.strip()

        # by technique ID
        if self._is_technique_id(q):
            tid = q.upper()
            return self.techniques_by_id.get(tid)

        nq = self._normalize(q)

        # exact technique name
        if nq in self.technique_name_map:
            technique_id = self.technique_name_map[nq]
            return self.techniques_by_id.get(technique_id)

        # partial name match
        for tname_norm, technique_id in self.technique_name_map.items():
            if nq in tname_norm:
                return self.techniques_by_id.get(technique_id)

        return None

    def _get_external_id_and_url(self, technique_obj: Dict[str, Any]) -> Dict[str, Optional[str]]:
        """
        Returns technique_id + url from external_references.
        """
        external_refs = technique_obj.get("external_references", []) or []
        technique_id = None
        url = None

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break

        return {"technique_id": technique_id, "url": url}

    def get_technique_details(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Returns detailed technique info for UI / AI summary.
        Works for:
        - T1055
        - Process Injection
        """
        self.load()

        t = self.find_technique(query)
        if not t:
            return None

        stix_id = t.get("id")
        name = t.get("name")
        description = t.get("description") or ""

        meta = self._get_external_id_and_url(t)
        technique_id = meta.get("technique_id")
        url = meta.get("url")

        # tactics for this technique
        tactics = []
        if stix_id and stix_id in self.technique_to_tactics:
            tactics = self.technique_to_tactics.get(stix_id, [])

        # mitigations
        mitigations: List[Dict[str, Any]] = []
        if stix_id and stix_id in self.technique_to_mitigations:
            for mid in self.technique_to_mitigations.get(stix_id, [])[:10]:
                mobj = self.mitigations_by_stix_id.get(mid)
                if not mobj:
                    continue
                said = mobj.get("name", "Mitigation")
                sdesc = (mobj.get("description") or "")[:400]
                mitigations.append({"name": said, "description": sdesc})

        return {
            "type": "technique",
            "technique_id": technique_id,
            "name": name,
            "description": description[:1200],
            "tactics": tactics,
            "url": url,
            "mitigations": mitigations
        }

    def get_tactic_details(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Returns tactic info.
        Works for:
        - Lateral Movement
        - lateral-movement
        """
        self.load()

        t = self.find_tactic(query)
        if not t:
            return None

        name = t.get("name")
        shortname = t.get("x_mitre_shortname")
        description = t.get("description") or ""

        return {
            "type": "tactic",
            "name": name,
            "shortname": shortname,
            "description": description[:1200]
        }

    def search_any(self, query: str) -> Dict[str, Any]:
        """
        Unified MITRE search:
        - group (APT + alias)
        - technique (Txxxx / name)
        - tactic (Lateral Movement)
        """
        self.load()

        result: Dict[str, Any] = {
            "matched": False,
            "match_type": None,  # group | technique | tactic
            "group": None,
            "technique": None,
            "tactic": None
        }

        # 1) Group match
        g = self.find_group(query)
        if g:
            result["matched"] = True
            result["match_type"] = "group"
            result["group"] = {
                "name": g.get("name"),
                "aliases": g.get("aliases", []) or [],
                "description": (g.get("description") or "")[:900]
            }
            # include top techniques for group
            result["group"]["top_techniques"] = self.get_group_techniques(g, limit=15)
            return result

        # 2) Technique match
        tech_details = self.get_technique_details(query)
        if tech_details:
            result["matched"] = True
            result["match_type"] = "technique"
            result["technique"] = tech_details
            return result

        # 3) Tactic match
        tactic_details = self.get_tactic_details(query)
        if tactic_details:
            result["matched"] = True
            result["match_type"] = "tactic"
            result["tactic"] = tactic_details
            return result

        return result
