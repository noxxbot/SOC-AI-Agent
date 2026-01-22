
import { GoogleGenAI, Type, GenerateContentResponse, Modality, Blob } from "@google/genai";
import { AnalysisResult, Incident, Playbook, BriefingResult, Telemetry, CorrelationResult } from "../types";

// Correctly uses process.env.API_KEY directly for initialization as per guidelines
export const getGeminiClient = () => {
  return new GoogleGenAI({ apiKey: process.env.API_KEY as string });
};

/**
 * Analyzes a log snippet for security threats
 */
export const analyzeLog = async (logText: string): Promise<AnalysisResult> => {
  const ai = getGeminiClient();
  const response = await ai.models.generateContent({
    model: 'gemini-3-pro-preview',
    contents: `Analyze the following system logs for security anomalies or signs of compromise. 
    Map the findings to specific threat vectors (0-100 score).
    Return a structured JSON response.
    
    Logs:
    ${logText}`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          riskScore: { type: Type.NUMBER, description: "Scale of 0-100" },
          threatDetected: { type: Type.BOOLEAN },
          explanation: { type: Type.STRING },
          recommendations: {
            type: Type.ARRAY,
            items: { type: Type.STRING }
          },
          threatVectors: {
            type: Type.OBJECT,
            properties: {
              persistence: { type: Type.NUMBER },
              lateralMovement: { type: Type.NUMBER },
              exfiltration: { type: Type.NUMBER },
              reconnaissance: { type: Type.NUMBER },
              credentialAccess: { type: Type.NUMBER }
            },
            required: ["persistence", "lateralMovement", "exfiltration", "reconnaissance", "credentialAccess"]
          }
        },
        required: ["riskScore", "threatDetected", "explanation", "recommendations", "threatVectors"]
      }
    }
  });

  return JSON.parse(response.text || '{}') as AnalysisResult;
};

/**
 * Correlates multiple alerts and telemetry for a holistic view
 */
export const correlateIncidentContext = async (
  primaryIncident: Incident, 
  relatedAlerts: Incident[], 
  telemetry: Telemetry[]
): Promise<CorrelationResult> => {
  const ai = getGeminiClient();
  const response = await ai.models.generateContent({
    model: 'gemini-1.5-flash',
    contents: `You are a Tier 3 SOC Lead. Correlate this primary incident with other recent events and telemetry for the same host.
    
    PRIMARY INCIDENT: ${JSON.stringify(primaryIncident)}
    RELATED ALERTS (Same Host): ${JSON.stringify(relatedAlerts)}
    TELEMETRY TRENDS: ${JSON.stringify(telemetry.slice(0, 10))}
    
    Provide a holistic summary, a relationship score (0-100) indicating how likely these are part of one campaign, and key insights.
    Return JSON.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING },
          relationshipScore: { type: Type.NUMBER },
          keyInsights: {
            type: Type.ARRAY,
            items: { type: Type.STRING }
          }
        },
        required: ["summary", "relationshipScore", "keyInsights"]
      }
    }
  });

  return JSON.parse(response.text || '{}') as CorrelationResult;
};

/**
 * Performs threat intelligence search with Google Search grounding
 */
export const searchThreatIntel = async (query: string) => {
  const ai = getGeminiClient();
  const response = await ai.models.generateContent({
    model: 'gemini-3-flash-preview',
    contents: `Perform a deep dive into this threat/vulnerability: ${query}. Provide IOCs, target sectors, and remediation steps.`,
    config: {
      tools: [{ googleSearch: {} }]
    }
  });

  const text = response.text || "";
  const sources = response.candidates?.[0]?.groundingMetadata?.groundingChunks
    ?.filter(chunk => chunk.web)
    .map(chunk => ({
      title: chunk.web?.title || 'External Source',
      uri: chunk.web?.uri || '#'
    })) || [];

  return { text, sources };
};

/**
 * Generates threat hunting playbooks based on an incident
 */
export const getPlaybookSuggestions = async (incident: Incident): Promise<Playbook[]> => {
  const ai = getGeminiClient();
  const response = await ai.models.generateContent({
    model: 'gemini-3-pro-preview',
    contents: `You are a senior SOC architect. Based on this security incident, generate 2 specific tactical threat hunting playbooks to identify lateral movement or persistence.
    
    Incident: ${JSON.stringify(incident)}
    
    Return a JSON array of Playbooks. Include complex, realistic queries for security tools.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.ARRAY,
        items: {
          type: Type.OBJECT,
          properties: {
            name: { type: Type.STRING, description: "Clear, tactical name of the playbook" },
            objective: { type: Type.STRING, description: "The specific hunting goal" },
            steps: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  action: { type: Type.STRING, description: "Detailed instruction for the analyst" },
                  query: { type: Type.STRING, description: "A realistic KQL/SQL/Splunk query" }
                },
                required: ["title", "action"]
              }
            }
          },
          required: ["name", "objective", "steps"]
        }
      }
    }
  });

  return JSON.parse(response.text || '[]') as Playbook[];
};

/**
 * Generates a concise tactical briefing and threat vector analysis for a security incident
 */
export const generateTacticalBriefing = async (incident: Incident): Promise<BriefingResult> => {
  const ai = getGeminiClient();
  const response = await ai.models.generateContent({
    model: 'gemini-3-pro-preview',
    contents: `As an AI security co-pilot, provide a concise tactical briefing and threat vector analysis for this incident.
    Return a structured JSON response.
    
    Incident: ${JSON.stringify(incident)}`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          brief: { type: Type.STRING, description: "The technical briefing text with IOCs and impact." },
          vectors: {
            type: Type.OBJECT,
            properties: {
              persistence: { type: Type.NUMBER },
              lateralMovement: { type: Type.NUMBER },
              exfiltration: { type: Type.NUMBER },
              reconnaissance: { type: Type.NUMBER },
              credentialAccess: { type: Type.NUMBER }
            },
            required: ["persistence", "lateralMovement", "exfiltration", "reconnaissance", "credentialAccess"]
          }
        },
        required: ["brief", "vectors"]
      }
    }
  });

  return JSON.parse(response.text || '{}') as BriefingResult;
};

export function encode(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function decode(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

export async function decodeAudioData(
  data: Uint8Array,
  ctx: AudioContext,
  sampleRate: number,
  numChannels: number,
): Promise<AudioBuffer> {
  const dataInt16 = new Int16Array(data.buffer);
  const frameCount = dataInt16.length / numChannels;
  const buffer = ctx.createBuffer(numChannels, frameCount, sampleRate);

  for (let channel = 0; channel < numChannels; channel++) {
    const channelData = buffer.getChannelData(channel);
    for (let i = 0; i < frameCount; i++) {
      channelData[i] = dataInt16[i * numChannels + channel] / 32768.0;
    }
  }
  return buffer;
}
