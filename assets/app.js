/**
 * Pulse — Log Forge
 * Frontend controller with Advanced Mode
 */
(function() {
    'use strict';

    const $ = id => document.getElementById(id);
    const btnGenerate = $('btn-generate');
    const btnPreview = $('btn-preview');
    const outputPanel = $('output-panel');
    const outputStats = $('output-stats');
    const outputActions = $('output-actions');
    const previewSection = $('preview-section');
    const previewHead = $('preview-head');
    const previewTail = $('preview-tail');
    const answerSection = $('answer-section');
    const btnToggleAnswers = $('btn-toggle-answers');
    const answerContent = $('answer-content');
    const answerJson = $('answer-json');
    const noiseSlider = $('noise_lines');
    const noiseOutput = $('noise_lines_val');
    const btnModeToggle = $('btn-mode-toggle');

    const fileLabels = {
        apache: 'access.log', nginx: 'nginx_access.log', iis: 'u_exYYMMDD.log',
        ssh: 'auth.log', windows: 'Security.csv', firewall: 'firewall.log',
    };

    let currentLogType = 'apache';
    let advancedMode = false;

    // ====== Advanced Mode Toggle ======
    btnModeToggle.addEventListener('click', () => {
        advancedMode = !advancedMode;
        btnModeToggle.classList.toggle('active', advancedMode);

        // Show/hide all advanced fields
        document.querySelectorAll('.adv-fields').forEach(f => {
            f.style.display = advancedMode ? 'block' : 'none';
        });
        document.querySelectorAll('.adv-only').forEach(f => {
            f.style.display = advancedMode ? 'block' : 'none';
        });
    });

    // ====== Log Type Switching ======
    document.querySelectorAll('.logtype-card').forEach(card => {
        card.addEventListener('click', () => {
            const radio = card.querySelector('input[type="radio"]');
            radio.checked = true;
            currentLogType = radio.value;

            // Update active card
            document.querySelectorAll('.logtype-card').forEach(c => c.classList.remove('active'));
            card.classList.add('active');

            // Hide ALL scenario groups, show the matching one
            document.querySelectorAll('.scenario-group').forEach(g => {
                g.style.display = 'none';
            });
            const target = $('scenarios-' + currentLogType);
            if (target) {
                target.style.display = 'block';
            }

            // Update description
            const descs = {
                apache: 'BrightMall e-commerce — Apache Combined Log Format',
                nginx: 'BrightMall e-commerce — Nginx with request timing fields',
                iis: 'NovaCRM intranet — IIS W3C Extended Log Format',
                ssh: 'Linux server — /var/log/auth.log (syslog)',
                windows: 'Windows Server — Security Event Log (CSV export)',
                firewall: 'Gateway — iptables kernel syslog',
            };
            $('scenario-desc').textContent = descs[currentLogType] || '';

            outputPanel.style.display = 'none';
        });
    });

    // ====== Slider ======
    noiseSlider.addEventListener('input', () => {
        noiseOutput.textContent = noiseSlider.value;
    });

    // ====== Answer Key Toggle ======
    let answersVisible = false;
    btnToggleAnswers.addEventListener('click', () => {
        answersVisible = !answersVisible;
        answerContent.style.display = answersVisible ? 'block' : 'none';
        btnToggleAnswers.textContent = answersVisible ? '🙈 Hide Answer Key' : '👁 Show Answer Key';
    });

    // ====== Collect Advanced Overrides ======
    function collectOverrides() {
        if (!advancedMode) return {};

        const overrides = {};
        const activeGroup = $('scenarios-' + currentLogType);
        if (!activeGroup) return overrides;

        // Collect all adv-input and adv-textarea values within the active group
        activeGroup.querySelectorAll('.adv-input, .adv-textarea').forEach(el => {
            const key = el.dataset.key;
            let val = el.value.trim();
            if (val === '') return; // skip empty = use default

            // Textareas with multiple lines → array
            if (el.tagName === 'TEXTAREA' && val.includes('\n')) {
                val = val.split('\n').map(l => l.trim()).filter(l => l.length > 0);
            } else if (el.tagName === 'TEXTAREA') {
                val = val ? [val] : [];
                if (val.length === 0) return;
            } else if (el.type === 'number') {
                val = parseInt(val);
                if (isNaN(val)) return;
            }

            overrides[key] = val;
        });

        // Global overrides (custom attacker IPs)
        const customIps = $('custom_attacker_ips').value.trim();
        if (customIps) {
            overrides.custom_attacker_ips = customIps.split('\n').map(l => l.trim()).filter(l => l.length > 0);
        }

        return overrides;
    }

    // ====== Gather Config ======
    function getConfig() {
        const activeGroup = $('scenarios-' + currentLogType);
        const scenarios = [];
        if (activeGroup) {
            activeGroup.querySelectorAll('.sc-check:checked').forEach(cb => {
                scenarios.push(cb.value);
            });
        }

        const config = {
            log_type: currentLogType,
            scenarios,
            noise_lines: parseInt(noiseSlider.value),
            difficulty: $('difficulty').value,
            attacker_count: parseInt($('attacker_count').value),
            time_span_hours: parseInt($('time_span').value),
        };

        const overrides = collectOverrides();
        if (Object.keys(overrides).length > 0) {
            config.overrides = overrides;
        }

        return config;
    }

    // ====== Generate ======
    async function generate(mode) {
        const config = getConfig();
        if (config.scenarios.length === 0) {
            alert('Select at least one attack scenario.');
            return;
        }
        config.output_mode = mode;

        btnGenerate.disabled = true;
        btnPreview.disabled = true;
        const origText = btnGenerate.innerHTML;
        btnGenerate.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Generating...';

        try {
            const resp = await fetch('/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            });
            const data = await resp.json();
            if (!data.success) throw new Error(data.error || 'Generation failed');

            outputPanel.style.display = 'block';
            const logLabel = fileLabels[config.log_type] || 'output.log';

            outputStats.innerHTML = `
                <span class="stat-item">Type: <strong>${logLabel}</strong></span>
                <span class="stat-item">Lines: <strong>${data.total_lines.toLocaleString()}</strong></span>
                <span class="stat-item">Scenarios: <strong>${config.scenarios.join(', ')}</strong></span>
                <span class="stat-item">Difficulty: <strong>${config.difficulty}</strong></span>
            `;

            if (mode === 'download' && data.download_url) {
                outputActions.innerHTML = `
                    <a href="${data.download_url}" class="btn-download" download>⬇ Download ${logLabel}</a>
                    <a href="${data.answer_url}" class="btn-download-answer" download>🔑 Download Answer Key</a>
                `;
            } else {
                outputActions.innerHTML = '';
            }

            if (data.preview_head) {
                previewSection.style.display = 'block';
                previewHead.textContent = data.preview_head.join('\n');
                previewTail.textContent = data.preview_tail.join('\n');
            } else {
                previewSection.style.display = 'none';
            }

            if (data.answers && Object.keys(data.answers).length > 0) {
                answerSection.style.display = 'block';
                answerJson.textContent = JSON.stringify(data.answers, null, 2);
                answersVisible = false;
                answerContent.style.display = 'none';
                btnToggleAnswers.textContent = '👁 Show Answer Key';
            }

            outputPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (err) {
            alert('Error: ' + err.message);
            console.error(err);
        } finally {
            btnGenerate.innerHTML = origText;
            btnGenerate.disabled = false;
            btnPreview.disabled = false;
        }
    }

    btnGenerate.addEventListener('click', () => generate('download'));
    btnPreview.addEventListener('click', () => generate('preview'));
})();
