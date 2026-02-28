<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pulse — Log Forge</title>
    <link rel="stylesheet" href="assets/style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="app">
        <!-- Header -->
        <header class="header">
            <div class="header-brand">
                <div class="logo-icon">
                    <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
                        <rect x="2" y="8" width="4" height="16" rx="1" fill="#00ff88" opacity="0.4"/>
                        <rect x="8" y="4" width="4" height="20" rx="1" fill="#00ff88" opacity="0.6"/>
                        <rect x="14" y="2" width="4" height="24" rx="1" fill="#00ff88" opacity="0.8"/>
                        <rect x="20" y="6" width="4" height="18" rx="1" fill="#00ff88"/>
                    </svg>
                </div>
                <h1>Pulse</h1>
                <span class="tag">log forge</span>
            </div>
            <div class="header-meta">
                <span class="status-dot"></span>
                <span>Ready</span>
            </div>
        </header>

        <!-- Main Content -->
        <main class="main">
            <!-- Scenario Selection -->
            <section class="panel">
                <h2 class="panel-title">Attack Scenarios</h2>
                <p class="panel-desc">Select which attack patterns to embed in the generated log.</p>
                <div class="scenario-grid">
                    <label class="scenario-card" data-scenario="lfi">
                        <input type="checkbox" name="scenario" value="lfi" checked>
                        <div class="card-inner">
                            <div class="card-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                    <polyline points="14,2 14,8 20,8"/>
                                    <line x1="9" y1="15" x2="15" y2="15"/>
                                </svg>
                            </div>
                            <div class="card-text">
                                <strong>LFI</strong>
                                <span>Path traversal & file inclusion via <code>page.php?file=</code></span>
                            </div>
                            <div class="check-mark">✓</div>
                        </div>
                    </label>

                    <label class="scenario-card" data-scenario="bruteforce">
                        <input type="checkbox" name="scenario" value="bruteforce" checked>
                        <div class="card-inner">
                            <div class="card-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                                </svg>
                            </div>
                            <div class="card-text">
                                <strong>Bruteforce</strong>
                                <span>Credential stuffing on <code>/account/login.php</code></span>
                            </div>
                            <div class="check-mark">✓</div>
                        </div>
                    </label>

                    <label class="scenario-card" data-scenario="webshell">
                        <input type="checkbox" name="scenario" value="webshell" checked>
                        <div class="card-inner">
                            <div class="card-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="4,17 10,11 4,5"/>
                                    <line x1="12" y1="19" x2="20" y2="19"/>
                                </svg>
                            </div>
                            <div class="card-text">
                                <strong>Webshell</strong>
                                <span>RCE via <code>.cache-img.php</code> in uploads</span>
                            </div>
                            <div class="check-mark">✓</div>
                        </div>
                    </label>
                </div>
            </section>

            <!-- Configuration -->
            <section class="panel">
                <h2 class="panel-title">Configuration</h2>
                <div class="config-grid">
                    <div class="config-item">
                        <label for="difficulty">Difficulty</label>
                        <select id="difficulty">
                            <option value="easy">Easy — obvious patterns, high volume</option>
                            <option value="medium" selected>Medium — mixed signals, moderate volume</option>
                            <option value="hard">Hard — stealthy, low & slow, obfuscated</option>
                        </select>
                    </div>
                    <div class="config-item">
                        <label for="noise_lines">Noise Lines</label>
                        <input type="range" id="noise_lines" min="100" max="3000" value="500" step="50">
                        <output id="noise_lines_val">500</output>
                    </div>
                    <div class="config-item">
                        <label for="attacker_count">Attacker IPs</label>
                        <select id="attacker_count">
                            <option value="1" selected>1 attacker</option>
                            <option value="2">2 attackers</option>
                            <option value="3">3 attackers</option>
                        </select>
                    </div>
                    <div class="config-item">
                        <label for="time_span">Time Span</label>
                        <select id="time_span">
                            <option value="1">1 hour</option>
                            <option value="3">3 hours</option>
                            <option value="6" selected>6 hours</option>
                            <option value="12">12 hours</option>
                            <option value="24">24 hours</option>
                        </select>
                    </div>
                </div>
            </section>

            <!-- Generate Button -->
            <div class="action-row">
                <button id="btn-generate" class="btn-primary">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polygon points="5,3 19,12 5,21"/>
                    </svg>
                    Generate Log
                </button>
                <button id="btn-preview" class="btn-secondary">Preview</button>
            </div>

            <!-- Output -->
            <section class="panel output-panel" id="output-panel" style="display:none;">
                <h2 class="panel-title">Output</h2>
                <div class="output-stats" id="output-stats"></div>
                <div class="output-actions" id="output-actions"></div>
                
                <!-- Preview -->
                <div id="preview-section" style="display:none;">
                    <div class="preview-block">
                        <h3>Log Preview <span class="preview-label">first 20 lines</span></h3>
                        <pre id="preview-head"></pre>
                    </div>
                    <div class="preview-block">
                        <h3>Log Tail <span class="preview-label">last 10 lines</span></h3>
                        <pre id="preview-tail"></pre>
                    </div>
                </div>

                <!-- Answer Key -->
                <div id="answer-section" style="display:none;">
                    <button id="btn-toggle-answers" class="btn-answer-toggle">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                        Show Answer Key
                    </button>
                    <div id="answer-content" class="answer-content" style="display:none;">
                        <pre id="answer-json"></pre>
                    </div>
                </div>
            </section>
        </main>

        <!-- Footer -->
        <footer class="footer">
            <span>Pulse Log Forge — for blue team training only</span>
        </footer>
    </div>

    <script src="assets/app.js"></script>
</body>
</html>
