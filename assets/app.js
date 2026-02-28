/**
 * Pulse — Log Forge
 * Frontend controller
 */

(function() {
    'use strict';

    // DOM refs
    const btnGenerate = document.getElementById('btn-generate');
    const btnPreview = document.getElementById('btn-preview');
    const outputPanel = document.getElementById('output-panel');
    const outputStats = document.getElementById('output-stats');
    const outputActions = document.getElementById('output-actions');
    const previewSection = document.getElementById('preview-section');
    const previewHead = document.getElementById('preview-head');
    const previewTail = document.getElementById('preview-tail');
    const answerSection = document.getElementById('answer-section');
    const btnToggleAnswers = document.getElementById('btn-toggle-answers');
    const answerContent = document.getElementById('answer-content');
    const answerJson = document.getElementById('answer-json');
    const noiseSlider = document.getElementById('noise_lines');
    const noiseOutput = document.getElementById('noise_lines_val');

    // Scenario containers
    const scenariosApache = document.getElementById('scenarios-apache');
    const scenariosSsh = document.getElementById('scenarios-ssh');

    // Log type cards
    const logTypeCards = document.querySelectorAll('.logtype-card');

    // Current log type
    let currentLogType = 'apache';

    // ============ Log Type Switching ============
    logTypeCards.forEach(card => {
        card.addEventListener('click', () => {
            const radio = card.querySelector('input[type="radio"]');
            radio.checked = true;
            currentLogType = radio.value;

            // Update active state
            logTypeCards.forEach(c => c.classList.remove('active'));
            card.classList.add('active');

            // Toggle scenario grids
            if (currentLogType === 'apache') {
                scenariosApache.style.display = '';
                scenariosSsh.style.display = 'none';
            } else if (currentLogType === 'ssh') {
                scenariosApache.style.display = 'none';
                scenariosSsh.style.display = '';
            }

            // Hide previous output
            outputPanel.style.display = 'none';
        });
    });

    // ============ Slider ============
    noiseSlider.addEventListener('input', () => {
        noiseOutput.textContent = noiseSlider.value;
    });

    // ============ Answer Key Toggle ============
    let answersVisible = false;
    btnToggleAnswers.addEventListener('click', () => {
        answersVisible = !answersVisible;
        answerContent.style.display = answersVisible ? 'block' : 'none';
        btnToggleAnswers.innerHTML = answersVisible
            ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg> Hide Answer Key'
            : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Show Answer Key';
    });

    /**
     * Gather config from UI
     */
    function getConfig() {
        const scenarios = [];

        if (currentLogType === 'apache') {
            document.querySelectorAll('#scenarios-apache input[name="scenario"]:checked').forEach(cb => {
                scenarios.push(cb.value);
            });
        } else if (currentLogType === 'ssh') {
            document.querySelectorAll('#scenarios-ssh input[name="scenario_ssh"]:checked').forEach(cb => {
                scenarios.push(cb.value);
            });
        }

        return {
            log_type: currentLogType,
            scenarios: scenarios,
            noise_lines: parseInt(noiseSlider.value),
            difficulty: document.getElementById('difficulty').value,
            attacker_count: parseInt(document.getElementById('attacker_count').value),
            time_span_hours: parseInt(document.getElementById('time_span').value),
        };
    }

    /**
     * Send generation request
     */
    async function generate(mode) {
        const config = getConfig();

        if (config.scenarios.length === 0) {
            alert('Select at least one attack scenario.');
            return;
        }

        config.output_mode = mode;

        // UI loading state
        btnGenerate.disabled = true;
        btnPreview.disabled = true;
        const origText = btnGenerate.innerHTML;
        btnGenerate.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Generating...';

        try {
            const resp = await fetch('generate.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            });

            const data = await resp.json();

            if (!data.success) {
                throw new Error(data.error || 'Generation failed');
            }

            // Show output panel
            outputPanel.style.display = 'block';

            // File label
            const logLabel = config.log_type === 'apache' ? 'access.log' : 'auth.log';

            // Stats
            outputStats.innerHTML = `
                <span class="stat-item">Type: <strong>${logLabel}</strong></span>
                <span class="stat-item">Lines: <strong>${data.total_lines.toLocaleString()}</strong></span>
                <span class="stat-item">Scenarios: <strong>${config.scenarios.join(', ')}</strong></span>
                <span class="stat-item">Difficulty: <strong>${config.difficulty}</strong></span>
            `;

            // Actions (download links)
            if (mode === 'download' && data.download_url) {
                outputActions.innerHTML = `
                    <a href="${data.download_url}" class="btn-download" download>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="7,10 12,15 17,10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Download ${logLabel}
                    </a>
                    <a href="${data.answer_url}" class="btn-download-answer" download>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14,2 14,8 20,8"/>
                        </svg>
                        Download Answer Key
                    </a>
                `;
            } else {
                outputActions.innerHTML = '';
            }

            // Preview
            if (data.preview_head) {
                previewSection.style.display = 'block';
                previewHead.textContent = data.preview_head.join('\n');
                previewTail.textContent = data.preview_tail.join('\n');
            } else {
                previewSection.style.display = 'none';
            }

            // Answer key
            if (data.answers && Object.keys(data.answers).length > 0) {
                answerSection.style.display = 'block';
                answerJson.textContent = JSON.stringify(data.answers, null, 2);
                answersVisible = false;
                answerContent.style.display = 'none';
                btnToggleAnswers.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Show Answer Key';
            }

            // Scroll to output
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

    // Event handlers
    btnGenerate.addEventListener('click', () => generate('download'));
    btnPreview.addEventListener('click', () => generate('preview'));

})();
