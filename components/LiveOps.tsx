
import React, { useState, useRef, useEffect } from 'react';
import { getGeminiClient, decode, encode, decodeAudioData } from '../services/gemini';
import { LiveServerMessage, Modality } from '@google/genai';

const LiveOps: React.FC = () => {
  const [isActive, setIsActive] = useState(false);
  const [transcription, setTranscription] = useState<string[]>([]);
  const [status, setStatus] = useState<'idle' | 'connecting' | 'listening' | 'speaking'>('idle');
  
  const audioContextRef = useRef<AudioContext | null>(null);
  const sessionRef = useRef<any>(null);
  const outputAudioContextRef = useRef<AudioContext | null>(null);
  const nextStartTimeRef = useRef<number>(0);
  const sourcesRef = useRef<Set<AudioBufferSourceNode>>(new Set());

  const toggleSession = async () => {
    if (isActive) {
      stopSession();
      return;
    }
    startSession();
  };

  const startSession = async () => {
    setStatus('connecting');
    setIsActive(true);

    try {
      // Create fresh client instance before connecting
      const ai = getGeminiClient();
      
      const inputCtx = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 16000 });
      const outputCtx = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 24000 });
      audioContextRef.current = inputCtx;
      outputAudioContextRef.current = outputCtx;

      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });

      const sessionPromise = ai.live.connect({
        model: 'gemini-2.5-flash-native-audio-preview-12-2025',
        callbacks: {
          onopen: () => {
            setStatus('listening');
            const source = inputCtx.createMediaStreamSource(stream);
            const scriptProcessor = inputCtx.createScriptProcessor(4096, 1, 1);
            
            scriptProcessor.onaudioprocess = (e) => {
              const inputData = e.inputBuffer.getChannelData(0);
              const l = inputData.length;
              const int16 = new Int16Array(l);
              for (let i = 0; i < l; i++) {
                int16[i] = inputData[i] * 32768;
              }
              const pcmBlob = {
                data: encode(new Uint8Array(int16.buffer)),
                mimeType: 'audio/pcm;rate=16000',
              };
              // Correct: Use sessionPromise to ensure data is sent to a resolved session
              sessionPromise.then(s => s.sendRealtimeInput({ media: pcmBlob }));
            };

            source.connect(scriptProcessor);
            scriptProcessor.connect(inputCtx.destination);
          },
          onmessage: async (message: LiveServerMessage) => {
            if (message.serverContent?.outputTranscription) {
               const text = message.serverContent.outputTranscription.text;
               setTranscription(prev => [...prev, `AI: ${text}`]);
            }
            if (message.serverContent?.inputTranscription) {
              const text = message.serverContent.inputTranscription.text;
              setTranscription(prev => [...prev, `You: ${text}`]);
           }

            const audioData = message.serverContent?.modelTurn?.parts[0]?.inlineData?.data;
            if (audioData) {
              setStatus('speaking');
              // Correct: Scheduling the next audio chunk using nextStartTimeRef
              nextStartTimeRef.current = Math.max(nextStartTimeRef.current, outputCtx.currentTime);
              const decodedBuffer = await decodeAudioData(decode(audioData), outputCtx, 24000, 1);
              const source = outputCtx.createBufferSource();
              source.buffer = decodedBuffer;
              source.connect(outputCtx.destination);
              source.onended = () => {
                sourcesRef.current.delete(source);
                if (sourcesRef.current.size === 0) setStatus('listening');
              };
              source.start(nextStartTimeRef.current);
              nextStartTimeRef.current += decodedBuffer.duration;
              sourcesRef.current.add(source);
            }
            
            if (message.serverContent?.interrupted) {
              sourcesRef.current.forEach(s => s.stop());
              sourcesRef.current.clear();
              nextStartTimeRef.current = 0;
            }
          },
          onerror: (e) => console.error('Live API Error:', e),
          onclose: () => stopSession(),
        },
        config: {
          responseModalities: [Modality.AUDIO],
          outputAudioTranscription: {},
          inputAudioTranscription: {},
          systemInstruction: "You are Sentinel AI, a tactical SOC operations assistant. You help security analysts with real-time triage, answering questions about threats, and providing guidance on incident response procedures. Keep your responses concise and professional."
        }
      });

      sessionRef.current = await sessionPromise;
    } catch (err) {
      console.error(err);
      setIsActive(false);
      setStatus('idle');
    }
  };

  const stopSession = () => {
    setIsActive(false);
    setStatus('idle');
    sessionRef.current?.close();
    audioContextRef.current?.close();
    outputAudioContextRef.current?.close();
  };

  useEffect(() => {
    return () => stopSession();
  }, []);

  return (
    <div className="max-w-4xl mx-auto h-[calc(100vh-12rem)] flex flex-col">
      <header className="mb-8 text-center">
        <h1 className="text-3xl font-bold text-slate-50">Live Operations Assistant</h1>
        <p className="text-slate-400">Voice-controlled hands-free triage and procedural guidance.</p>
      </header>

      <div className="flex-1 bg-slate-900 border border-slate-800 rounded-3xl p-8 flex flex-col shadow-2xl overflow-hidden">
        <div className="flex-1 overflow-y-auto space-y-4 mb-6 pr-4 custom-scrollbar">
          {transcription.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-600 text-center opacity-50">
               <i className="fa-solid fa-waveform text-5xl mb-4"></i>
               <p>Initiate tactical link to begin voice-assisted operations</p>
            </div>
          ) : (
            transcription.map((t, i) => (
              <div key={i} className={`flex ${t.startsWith('You:') ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[80%] px-4 py-2 rounded-2xl ${
                  t.startsWith('You:') ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-200'
                }`}>
                  <p className="text-sm font-medium">{t.split(': ')[1]}</p>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="flex flex-col items-center gap-6">
          <div className="flex items-center gap-4">
            <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest ${
              status === 'listening' ? 'bg-emerald-500/20 text-emerald-500 animate-pulse' :
              status === 'speaking' ? 'bg-blue-500/20 text-blue-500' :
              status === 'connecting' ? 'bg-amber-500/20 text-amber-500' : 'bg-slate-800 text-slate-500'
            }`}>
              <div className={`w-2 h-2 rounded-full ${
                status === 'listening' ? 'bg-emerald-500' :
                status === 'speaking' ? 'bg-blue-500' :
                status === 'connecting' ? 'bg-amber-500' : 'bg-slate-600'
              }`}></div>
              {status}
            </div>
          </div>

          <button
            onClick={toggleSession}
            className={`w-20 h-20 rounded-full flex items-center justify-center transition-all shadow-lg ${
              isActive 
                ? 'bg-rose-600 hover:bg-rose-500 text-white scale-110' 
                : 'bg-emerald-600 hover:bg-emerald-500 text-white hover:scale-105'
            }`}
          >
            <i className={`fa-solid ${isActive ? 'fa-phone-slash' : 'fa-headset'} text-2xl`}></i>
          </button>
          
          <p className="text-xs text-slate-500 font-mono">
            {isActive ? 'TACTICAL LINK ESTABLISHED' : 'READY FOR LINK INITIATION'}
          </p>
        </div>
      </div>
    </div>
  );
};

export default LiveOps;
