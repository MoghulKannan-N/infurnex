import React, { useState, useEffect, useRef, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  Plus, Terminal, Shield, AlertTriangle,
  Send, CheckCircle, Cpu, Activity, Command,
  Layers, Globe, Sparkles, Brain, Settings,
  StopCircle, MessageSquare, Trash2, ChevronRight,
  PanelLeftClose, PanelLeftOpen, X
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

// ── helpers ──────────────────────────────────────────────────────────────────
const getTime = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const genId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

const WELCOME_MSG = {
  id: 'welcome',
  role: 'ai',
  segments: [{ type: 'text', content: '### ⚡ Infurnex Deep-Triage\n\nSystems online. I can execute commands, analyze logs, and perform autonomous reconnaissance.\n\nAsk anything or give me a target to investigate.' }],
  time: 'now',
  verified: true,
  thoughts: [],
};

const STORAGE_KEY = 'infurnex_sessions';

function loadSessions() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch { return []; }
}

function saveSessions(sessions) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions)); } catch { }
}

// ── SIEM data ─────────────────────────────────────────────────────────────────
const METRICS = { events: '1.2M', threats: 42, blocked: 890, uptime: '99.99%' };
const LOGS = [
  { id: 1, time: '00:10:45', source: '192.168.1.45', event: 'SSH Brute Force Attempt', severity: 'high' },
  { id: 2, time: '00:10:48', source: 'WAF-Primary', event: 'SQL Injection Blocked (POST /api/v1/login)', severity: 'medium' },
  { id: 3, time: '00:11:02', source: 'Auth-Svc', event: 'Multiple Failed Root Logins', severity: 'critical' },
  { id: 4, time: '00:11:15', source: 'Egress-GW', event: 'Unusual Data Transfer (4.2GB to unknown IP)', severity: 'high' },
];

// ── Segment renderer ──────────────────────────────────────────────────────────
function Segment({ seg, i }) {
  if (seg.type === 'cmd') return (
    <div key={i} className="my-4 rounded-2xl overflow-hidden border border-white/10 bg-black/50">
      <div className="px-4 py-2 bg-white/5 border-b border-white/5 text-[9px] font-black uppercase tracking-[0.3em] text-white/30">EXECUTE</div>
      <div className="px-4 py-3 text-blue-400 font-mono font-bold text-[14px]">$ {seg.content}</div>
    </div>
  );
  if (seg.type === 'out') return (
    <pre key={i} className="my-2 mb-6 p-4 rounded-xl bg-black/40 border border-white/5 text-[13px] font-mono text-white/80 whitespace-pre-wrap leading-relaxed overflow-x-auto">{seg.content}</pre>
  );
  if (seg.type === 'report') return (
    <div key={i} className="my-4 p-5 rounded-2xl bg-green/10 border border-green/20">
      <div className="text-[10px] font-black uppercase tracking-widest text-green mb-2">✅ Final Report</div>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={{ p: ({ node, ...p }) => <p className="text-white/80 text-sm leading-relaxed" {...p} /> }}>
        {seg.content}
      </ReactMarkdown>
    </div>
  );
  return (
    <ReactMarkdown
      key={i}
      remarkPlugins={[remarkGfm]}
      components={{
        p: ({ node, ...p }) => <p className="mb-4 last:mb-0" {...p} />,
        a: ({ node, ...p }) => <a className="text-accent underline hover:no-underline font-medium" {...p} />,
        ul: ({ node, ...p }) => <ul className="list-disc ml-6 mb-4 space-y-1" {...p} />,
        ol: ({ node, ...p }) => <ol className="list-decimal ml-6 mb-4 space-y-1" {...p} />,
        h3: ({ node, ...p }) => <h3 className="text-base font-black mt-4 mb-2" {...p} />,
        code: ({ node, inline, ...p }) =>
          inline
            ? <code className="bg-white/10 px-1.5 py-0.5 rounded text-[13px] font-mono text-blue-300" {...p} />
            : <pre className="my-4 bg-black/40 p-4 rounded-xl overflow-x-auto text-[13px] font-mono"><code {...p} /></pre>,
      }}
    >
      {seg.content}
    </ReactMarkdown>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
const App = () => {
  const [view, setView] = useState('chat');
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [modals, setModals] = useState({ sandbox: false, triage: false });
  const [expandedThoughts, setExpandedThoughts] = useState({});
  const [showHistory, setShowHistory] = useState(false);

  // ── Session management ───────────────────────────────────────────────────
  const [sessions, setSessions] = useState(() => loadSessions());
  const [currentId, setCurrentId] = useState(null);

  const currentSession = sessions.find(s => s.id === currentId) || null;
  const messages = currentSession?.messages || [WELCOME_MSG];

  const setMessages = useCallback((updater) => {
    setSessions(prev => prev.map(s =>
      s.id !== currentId ? s : {
        ...s,
        messages: typeof updater === 'function' ? updater(s.messages) : updater,
      }
    ));
  }, [currentId]);

  // Persist sessions to localStorage whenever they change
  useEffect(() => { saveSessions(sessions); }, [sessions]);

  // ── Abort / stop ─────────────────────────────────────────────────────────
  const abortRef = useRef(null);

  const stopGeneration = () => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
    setIsTyping(false);
  };

  // ── Scroll ────────────────────────────────────────────────────────────────
  const messagesEndRef = useRef(null);
  const scrollBottom = () => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  useEffect(() => { scrollBottom(); }, [messages, isTyping, view, currentId]);

  // ── New chat ──────────────────────────────────────────────────────────────
  const newChat = () => {
    const id = genId();
    const now = getTime();
    const session = {
      id,
      title: 'New Investigation',
      createdAt: now,
      messages: [{ ...WELCOME_MSG, id: genId(), time: now }],
    };
    setSessions(prev => [session, ...prev]);
    setCurrentId(id);
    setExpandedThoughts({});
  };

  // Create a default session on first load if there are none
  useEffect(() => {
    if (sessions.length === 0) {
      newChat();
    } else {
      setCurrentId(sessions[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadSession = (id) => {
    setCurrentId(id);
    setExpandedThoughts({});
    setShowHistory(false);
  };

  const deleteSession = (id, e) => {
    e.stopPropagation();
    setSessions(prev => {
      const next = prev.filter(s => s.id !== id);
      if (currentId === id) {
        if (next.length > 0) setCurrentId(next[0].id);
        else newChat();
      }
      return next;
    });
  };

  // ── Send message ──────────────────────────────────────────────────────────
  const sendMessage = async (customText = null) => {
    const text = customText || input.trim();
    if (!text || isTyping) return;
    if (!customText) setInput('');
    setIsTyping(true);

    // Update session title from first real user message
    setSessions(prev => prev.map(s =>
      s.id !== currentId ? s : {
        ...s,
        title: s.title === 'New Investigation' ? text.slice(0, 48) : s.title,
      }
    ));

    const userMsg = { id: genId(), role: 'user', segments: [{ type: 'text', content: text }], time: getTime() };
    setSessions(prev => prev.map(s =>
      s.id !== currentId ? s : { ...s, messages: [...s.messages, userMsg] }
    ));

    const aiMsgId = genId();
    setSessions(prev => prev.map(s =>
      s.id !== currentId ? s : {
        ...s,
        messages: [...s.messages, { id: aiMsgId, role: 'ai', segments: [], time: getTime(), isLoading: true, thoughts: [] }],
      }
    ));

    let pendingText = '';
    let thoughts = [];
    const controller = new AbortController();
    abortRef.current = controller;

    const flushText = () => {
      if (!pendingText) return;
      const snap = pendingText;
      pendingText = '';
      setSessions(prev => prev.map(s =>
        s.id !== currentId ? s : {
          ...s,
          messages: s.messages.map(m =>
            m.id !== aiMsgId ? m : {
              ...m, isLoading: false,
              segments: [...m.segments.filter(sg => sg._live !== true), { type: 'text', content: snap }],
              thoughts: [...thoughts],
            }
          ),
        }
      ));
    };

    const pushSegment = (seg) => {
      flushText();
      setSessions(prev => prev.map(s =>
        s.id !== currentId ? s : {
          ...s,
          messages: s.messages.map(m =>
            m.id !== aiMsgId ? m : {
              ...m, isLoading: false,
              segments: [...m.segments, seg],
              thoughts: [...thoughts],
            }
          ),
        }
      ));
    };

    try {
      const response = await fetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text }),
        signal: controller.signal,
      });

      if (!response.ok) {
        pushSegment({ type: 'text', content: `⚠️ Server error (${response.status}). Check that the backend is running.` });
        setIsTyping(false);
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const raw = decoder.decode(value);
        for (const line of raw.split('\n')) {
          if (!line.startsWith('data:')) continue;
          const chunk = line.slice(5);
          const chunkTrimmed = chunk.trim();
          if (chunkTrimmed === '[DONE]') { flushText(); continue; }
          if (!chunkTrimmed) continue;

          if (chunkTrimmed.startsWith('thought:')) {
            thoughts.push(chunkTrimmed.slice(8).replace(/⏎/g, '\n'));
          } else if (chunkTrimmed.startsWith('cmd:')) {
            pushSegment({ type: 'cmd', content: chunkTrimmed.slice(4).replace(/⏎/g, '\n') });
          } else if (chunkTrimmed.startsWith('out:')) {
            pushSegment({ type: 'out', content: chunkTrimmed.slice(4).replace(/⏎/g, '\n') });
          } else if (chunkTrimmed.startsWith('report:')) {
            pushSegment({ type: 'report', content: chunkTrimmed.slice(7).replace(/⏎/g, '\n') });
          } else {
            pendingText += chunk.replace(/⏎/g, '\n');
            const snap = pendingText;
            setSessions(prev => prev.map(s =>
              s.id !== currentId ? s : {
                ...s,
                messages: s.messages.map(m =>
                  m.id !== aiMsgId ? m : {
                    ...m, isLoading: false,
                    segments: [...m.segments.filter(sg => sg._live !== true), { type: 'text', content: snap, _live: true }],
                    thoughts: [...thoughts],
                  }
                ),
              }
            ));
          }
        }
      }
      flushText();
    } catch (err) {
      if (err.name !== 'AbortError') {
        pushSegment({ type: 'text', content: '⚠️ Connection lost. Server may be down.' });
      } else {
        // Aborted — finalize whatever we have
        flushText();
        setSessions(prev => prev.map(s =>
          s.id !== currentId ? s : {
            ...s,
            messages: s.messages.map(m =>
              m.id !== aiMsgId ? m : { ...m, isLoading: false, _stopped: true }
            ),
          }
        ));
      }
    } finally {
      abortRef.current = null;
      setIsTyping(false);
    }
  };

  const toggleThought = (id) => setExpandedThoughts(prev => ({ ...prev, [id]: !prev[id] }));
  const toggleModal = (modal) => setModals(prev => ({ ...prev, [modal]: !prev[modal] }));

  const renderMessageContent = (msg) => {
    if (msg.role === 'user') return <p className="text-[15px]">{msg.segments?.[0]?.content ?? ''}</p>;
    return <>{(msg.segments || []).map((s, i) => <Segment key={i} seg={s} i={i} />)}</>;
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-bg text-white font-sans selection:bg-accent/30">
      {/* ── Sidebar nav ──────────────────────────────────────────────────── */}
      <nav className="flex-shrink-0 w-[60px] border-r border-white/5 flex flex-col items-center py-6 gap-6 glass z-50">
        {/* Logo / new chat */}
        <button
          onClick={newChat}
          className="w-10 h-10 rounded-xl flex items-center justify-center bg-accent text-white shadow-lg shadow-accent/20 hover:bg-accent-h transition-all"
          title="New Chat"
        >
          <Plus size={20} />
        </button>

        <div className="flex flex-col gap-5 flex-1">
          <button
            onClick={() => { setView('chat'); setShowHistory(false); }}
            className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${view === 'chat' && !showHistory ? 'text-accent' : 'text-muted hover:text-white'}`}
            title="Chat"
          >
            <Command size={20} />
          </button>

          <button
            onClick={() => setShowHistory(v => !v)}
            className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${showHistory ? 'text-accent' : 'text-muted hover:text-white'}`}
            title="Chat History"
          >
            <MessageSquare size={20} />
          </button>

          <button
            onClick={() => { setView('analytics'); setShowHistory(false); }}
            className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${view === 'analytics' ? 'text-accent' : 'text-muted hover:text-white'}`}
            title="SIEM Analytics"
          >
            <Activity size={20} />
          </button>

          <Layers size={20} className="text-muted hover:text-white cursor-pointer transition-colors" />
          <Globe size={20} className="text-muted hover:text-white cursor-pointer transition-colors" />
        </div>

        <Settings size={20} className="text-muted hover:text-white cursor-pointer transition-colors" />
      </nav>

      {/* ── History panel (slide-in) ──────────────────────────────────────── */}
      <AnimatePresence>
        {showHistory && (
          <motion.aside
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 280, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeInOut' }}
            className="flex-shrink-0 border-r border-white/5 flex flex-col glass z-40 overflow-hidden"
            style={{ width: 280 }}
          >
            <div className="p-5 border-b border-white/5 flex items-center justify-between">
              <span className="text-[10px] font-black uppercase tracking-[0.3em] text-muted/60">Investigations</span>
              <button onClick={() => setShowHistory(false)} className="text-muted hover:text-white transition-colors">
                <X size={14} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto custom-scrollbar p-3 flex flex-col gap-2">
              {sessions.length === 0 && (
                <p className="text-[12px] text-muted/40 text-center py-8">No sessions yet</p>
              )}
              {sessions.map(s => (
                <button
                  key={s.id}
                  onClick={() => loadSession(s.id)}
                  className={`w-full text-left p-3 rounded-xl group flex items-start gap-3 transition-all ${s.id === currentId ? 'bg-accent/10 border border-accent/20' : 'hover:bg-white/5 border border-transparent'}`}
                >
                  <MessageSquare size={14} className={`mt-0.5 flex-shrink-0 ${s.id === currentId ? 'text-accent' : 'text-muted/50'}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-semibold truncate">{s.title}</p>
                    <p className="text-[10px] text-muted/40">{s.createdAt}</p>
                  </div>
                  <button
                    onClick={(e) => deleteSession(s.id, e)}
                    className="opacity-0 group-hover:opacity-100 text-muted/40 hover:text-red-400 transition-all flex-shrink-0"
                  >
                    <Trash2 size={12} />
                  </button>
                </button>
              ))}
            </div>
            <div className="p-4 border-t border-white/5">
              <button
                onClick={newChat}
                className="w-full py-3 rounded-xl bg-accent/10 hover:bg-accent/20 border border-accent/20 text-[11px] font-black uppercase tracking-widest text-accent transition-all flex items-center justify-center gap-2"
              >
                <Plus size={14} /> New Investigation
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <main className="flex-1 flex flex-col min-w-0 relative">
        {/* Header */}
        <header className="flex-shrink-0 h-[60px] px-8 flex items-center justify-between border-b border-white/5 glass z-40">
          <div className="flex items-center gap-4">
            <h1 className="text-base font-black tracking-tight">
              {view === 'chat' ? 'INFURNEX' : 'SIEM ANALYTICS'}
              <span className="text-accent font-mono text-[10px] ml-2 opacity-50">v2.1.2</span>
            </h1>
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-green/10 border border-green/20">
              <div className="w-1.5 h-1.5 rounded-full bg-green animate-pulse" />
              <span className="text-[10px] uppercase font-bold text-green tracking-widest">
                {view === 'chat' ? 'System Active' : 'Live Telemetry'}
              </span>
            </div>
            {currentSession && view === 'chat' && (
              <span className="text-[11px] text-muted/40 truncate max-w-[200px]">{currentSession.title}</span>
            )}
          </div>
          <div className="flex gap-3">
            <button onClick={() => toggleModal('sandbox')} className="px-4 py-2 rounded-xl text-xs font-bold bg-white/5 hover:bg-white/10 border border-white/10 transition-all flex items-center gap-2">
              <Sparkles size={14} className="text-yellow-400" /> Sandbox
            </button>
            <button onClick={() => toggleModal('triage')} className="px-4 py-2 rounded-xl text-xs font-bold bg-white/5 hover:bg-white/10 border border-white/10 transition-all flex items-center gap-2">
              <Shield size={14} className="text-accent" /> Triage
            </button>
          </div>
        </header>

        {view === 'chat' ? (
          <>
            {/* Messages */}
            <div className="flex-1 overflow-y-auto px-4 sm:px-8 py-8 custom-scrollbar">
              <div className="max-w-5xl mx-auto flex flex-col gap-8">
                <AnimatePresence initial={false}>
                  {messages.map((msg) => (
                    <motion.div
                      key={msg.id}
                      initial={{ opacity: 0, y: 16 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={`flex gap-4 w-full ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                    >
                      <div className={`w-9 h-9 rounded-xl flex-shrink-0 flex items-center justify-center text-[9px] font-black tracking-tighter ${msg.role === 'user' ? 'bg-accent text-white shadow-lg shadow-accent/20' : 'glass border-white/10 text-muted'}`}>
                        {msg.role === 'user' ? 'YOU' : 'AI'}
                      </div>

                      <div className={`flex flex-col gap-2 min-w-0 flex-1 ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                        <div className={`message-bubble overflow-hidden relative ${msg.role === 'user' ? 'user-bubble shadow-xl shadow-accent/10 ml-10' : 'ai-bubble mr-4'}`}>
                          {msg.isLoading ? (
                            <div className="flex gap-1.5 py-2 px-1">
                              <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0s' }} />
                              <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                              <span className="w-1.5 h-1.5 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0.4s' }} />
                            </div>
                          ) : (
                            <>
                              {msg._stopped && (
                                <div className="text-[10px] font-bold text-orange-400 mb-3 flex items-center gap-2">
                                  <StopCircle size={12} /> Generation stopped
                                </div>
                              )}
                              {renderMessageContent(msg)}

                              {msg.role === 'ai' && msg.thoughts && msg.thoughts.length > 0 && (
                                <div className="mt-6 pt-5 border-t border-white/5">
                                  <button
                                    onClick={() => toggleThought(msg.id)}
                                    className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.3em] text-accent hover:text-white transition-all group mb-3"
                                  >
                                    <Brain size={12} className="group-hover:rotate-12 transition-transform" />
                                    {expandedThoughts[msg.id] ? 'Conceal Logic' : 'Inspect Reasoning'}
                                  </button>

                                  <AnimatePresence>
                                    {expandedThoughts[msg.id] && (
                                      <motion.div
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: 'auto', opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        className="overflow-hidden"
                                      >
                                        <div className="p-5 rounded-2xl bg-black/40 border border-white/5 text-[14px] text-white/80 leading-relaxed font-mono shadow-inner">
                                          <div className="flex flex-col gap-3">
                                            {msg.thoughts.map((t, i) => {
                                              const isObserve = t.startsWith('🔍');
                                              const isHypothesize = t.startsWith('💡');
                                              const isAct = t.startsWith('⚡');
                                              const labelColor = isObserve ? 'text-blue-400' : isHypothesize ? 'text-yellow-400' : isAct ? 'text-green' : 'text-accent/60';
                                              const bgColor = isObserve ? 'bg-blue-500/5 border-blue-500/10' : isHypothesize ? 'bg-yellow-500/5 border-yellow-500/10' : isAct ? 'bg-green/5 border-green/10' : 'bg-white/5 border-white/5';
                                              // Split "EMOJI LABEL — content" into label and body
                                              const dashIdx = t.indexOf(' — ');
                                              const label = dashIdx !== -1 ? t.slice(0, dashIdx) : `#${String(i + 1).padStart(2, '0')}`;
                                              const body = dashIdx !== -1 ? t.slice(dashIdx + 3) : t;
                                              return (
                                                <div key={i} className={`rounded-xl border p-3 ${bgColor}`}>
                                                  <div className={`text-[9px] font-black uppercase tracking-widest mb-1.5 ${labelColor}`}>{label}</div>
                                                  <span className="flex-1 opacity-90 text-[12px] leading-relaxed">{body}</span>
                                                </div>
                                              );
                                            })}
                                          </div>
                                        </div>
                                      </motion.div>
                                    )}
                                  </AnimatePresence>
                                </div>
                              )}
                            </>
                          )}
                        </div>

                        <div className="flex items-center gap-3 px-2 text-[10px] text-muted/50 font-bold uppercase tracking-[0.15em]">
                          <span>{msg.time}</span>
                          {msg.verified && <span className="text-green flex items-center gap-1"><CheckCircle size={10} /> Validated Intel</span>}
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
                <div ref={messagesEndRef} />
              </div>
            </div>

            {/* Input bar */}
            <div className="flex-shrink-0 px-6 sm:px-8 pb-6 pt-3 bg-gradient-to-t from-bg via-bg/95 to-transparent">
              <div className="max-w-5xl mx-auto relative group">
                <div className="absolute -inset-2 bg-gradient-to-r from-accent/20 via-blue-500/5 to-accent/20 rounded-[32px] blur-2xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-700 pointer-events-none" />
                <div className="relative glass p-2 pr-3 rounded-[24px] flex items-center gap-3 border-white/10 focus-within:border-accent/50 transition-all shadow-2xl backdrop-blur-3xl">
                  <button onClick={newChat} className="w-10 h-10 flex items-center justify-center text-muted hover:text-white transition-colors flex-shrink-0">
                    <Plus size={20} />
                  </button>
                  <input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && !isTyping && sendMessage()}
                    placeholder="Target description or investigation goal..."
                    className="flex-1 bg-transparent border-none outline-none text-[15px] py-3 placeholder:text-muted/30 font-medium"
                  />

                  {isTyping ? (
                    <button
                      onClick={stopGeneration}
                      className="h-11 px-5 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 text-red-400 text-[11px] font-black uppercase tracking-widest transition-all flex items-center gap-2 flex-shrink-0"
                    >
                      <StopCircle size={14} /> Stop
                    </button>
                  ) : (
                    <button
                      onClick={() => sendMessage()}
                      disabled={!input.trim()}
                      className="h-11 px-6 rounded-xl bg-accent hover:bg-accent-h text-white text-[11px] font-black uppercase tracking-widest transition-all disabled:grayscale disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-2 shadow-lg shadow-accent/20 flex-shrink-0"
                    >
                      Execute <Send size={13} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          </>
        ) : (
          /* SIEM ANALYTICS */
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex-1 p-10 overflow-y-auto custom-scrollbar">
            <div className="max-w-6xl mx-auto flex flex-col gap-10">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {[
                  { label: 'Ingested Events', value: METRICS.events, icon: Activity, color: 'text-blue-400' },
                  { label: 'Critical Threats', value: METRICS.threats, icon: AlertTriangle, color: 'text-red-400' },
                  { label: 'Active Blocks', value: METRICS.blocked, icon: Shield, color: 'text-green-400' },
                  { label: 'Infurnex Uptime', value: METRICS.uptime, icon: Cpu, color: 'text-accent' },
                ].map((m, i) => (
                  <motion.div key={i} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}
                    className="glass p-6 rounded-3xl border border-white/5 flex flex-col gap-4">
                    <div className={`w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center ${m.color}`}><m.icon size={20} /></div>
                    <div>
                      <div className="text-[10px] text-muted font-black uppercase tracking-widest mb-1">{m.label}</div>
                      <div className="text-2xl font-black tracking-tight">{m.value}</div>
                    </div>
                  </motion.div>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-10">
                <div className="lg:col-span-2 flex flex-col gap-6">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-black uppercase tracking-[0.3em] text-muted/60 flex items-center gap-3"><Terminal size={14} /> Real-Time Security Feed</h2>
                    <div className="px-3 py-1 rounded-full bg-accent/10 border border-accent/20 text-[10px] font-bold text-accent uppercase tracking-widest">Live Stream</div>
                  </div>
                  <div className="glass rounded-[28px] border border-white/5 overflow-hidden">
                    <table className="w-full text-left">
                      <thead className="bg-white/5 text-[10px] font-black uppercase tracking-widest text-muted/60">
                        <tr>{['Timestamp', 'Source', 'Event', 'Risk'].map(h => <th key={h} className="px-6 py-4">{h}</th>)}</tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 font-mono text-[12px]">
                        {LOGS.map(log => (
                          <tr key={log.id} className="hover:bg-white/5 transition-colors">
                            <td className="px-6 py-4 text-muted">{log.time}</td>
                            <td className="px-6 py-4 font-bold text-accent">{log.source}</td>
                            <td className="px-6 py-4 text-white/80">{log.event}</td>
                            <td className="px-6 py-4">
                              <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-widest ${log.severity === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : log.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'}`}>
                                {log.severity}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="flex flex-col gap-6">
                  <h2 className="text-sm font-black uppercase tracking-[0.3em] text-muted/60 flex items-center gap-3"><Brain size={14} className="text-accent" /> Supervisor Panel</h2>
                  <div className="glass p-8 rounded-[28px] border border-white/10 bg-accent/5 relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-4 opacity-10"><Brain size={80} /></div>
                    <div className="relative z-10">
                      <div className="text-[10px] font-black uppercase tracking-[0.2em] text-accent mb-6 flex items-center gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" /> Infurnex AI Active
                      </div>
                      <div className="space-y-4">
                        <div className="p-4 rounded-2xl bg-black/40 border border-white/5">
                          <div className="text-[9px] font-black text-muted uppercase tracking-widest mb-1">Latest Verdict</div>
                          <div className="text-sm font-bold text-white mb-2 leading-snug">"Auto-triaged SSH attempt from 192.168.1.45. Triggered defensive port-knock sequence."</div>
                          <div className="flex items-center gap-2 text-[10px] text-green font-bold uppercase tracking-widest"><CheckCircle size={12} /> Resolved</div>
                        </div>
                        <div className="p-4 rounded-2xl bg-black/20 border border-white/5 opacity-50">
                          <div className="text-[9px] font-black text-muted uppercase tracking-widest mb-1">Previous Insight</div>
                          <div className="text-sm font-medium text-white/50 leading-snug">"Anomalous traffic observed in Egress-GW. Suggesting packet inspection on port 443."</div>
                        </div>
                      </div>
                      <button className="w-full mt-6 py-4 rounded-2xl bg-accent hover:bg-accent-h text-white font-black text-[10px] uppercase tracking-widest transition-all shadow-lg shadow-accent/20">View Full Reasoning</button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </main>

      {/* ── Modals ────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {modals.sandbox && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[100] bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
            <motion.div initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }} className="glass max-w-md w-full p-10 rounded-[40px] shadow-2xl border border-white/10">
              <div className="flex items-center gap-4 text-2xl font-black tracking-tight mb-8">
                <div className="w-12 h-12 rounded-2xl bg-accent flex items-center justify-center text-white"><Cpu size={24} /></div>
                Sandbox Environment
              </div>
              <div className="space-y-4 mb-10">
                {[{ label: 'Initializing hardened kernel...', done: true }, { label: 'Mounting encrypted volumes...', active: true }, { label: 'Securing network mesh...' }].map((s, idx) => (
                  <div key={idx} className="flex items-center gap-5 py-2 text-[15px]">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-black ${s.done ? 'bg-green text-black' : s.active ? 'bg-accent text-white' : 'bg-white/5 text-muted'}`}>{s.done ? '✓' : idx + 1}</div>
                    <span className={s.done ? 'text-white/60' : s.active ? 'text-accent animate-pulse font-bold' : 'text-muted'}>{s.label}</span>
                  </div>
                ))}
              </div>
              <button onClick={() => toggleModal('sandbox')} className="w-full py-5 rounded-2xl bg-white/5 hover:bg-white/10 font-black text-[11px] uppercase tracking-[0.2em] transition-all border border-white/5">Deactivate</button>
            </motion.div>
          </motion.div>
        )}
        {modals.triage && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[100] bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
            <motion.div initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }} className="glass max-w-md w-full p-10 rounded-[40px] shadow-2xl border border-white/10">
              <div className="flex items-center gap-4 text-2xl font-black tracking-tight mb-8">
                <div className="w-12 h-12 rounded-2xl bg-green flex items-center justify-center text-black"><Shield size={24} /></div>
                Threat Intelligence
              </div>
              <div className="p-8 rounded-3xl bg-black/40 border border-white/5 mb-10">
                <div className="text-[10px] text-muted/60 mb-3 uppercase tracking-[0.3em] font-black">Live Assessment</div>
                <div className="text-3xl font-black text-green flex items-center gap-4">Secured <CheckCircle size={32} /></div>
                <div className="mt-4 pt-4 border-t border-white/5 flex justify-between text-[11px] font-black uppercase tracking-widest text-muted/60">
                  <span>Latency: 0.04ms</span><span>Trust: 99.8%</span>
                </div>
              </div>
              <button onClick={() => toggleModal('triage')} className="w-full py-5 rounded-2xl bg-white/5 hover:bg-white/10 font-black text-[11px] uppercase tracking-[0.2em] transition-all border border-white/5">Close Pipeline</button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default App;
