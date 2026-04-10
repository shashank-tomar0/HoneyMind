/**
 * HoneyShield Telemetry Engine
 * Silently extracts behavioral features (ML Phase 2 context) from the DOM.
 */

const Telemetry = {
  data: {
    page_load_time: Date.now(),
    mouse_move_count: 0,
    keystroke_intervals: [],
    last_keystroke_time: 0,
    backspace_count: 0,
    time_to_submit_s: 0,
    pasted_password: false,
    tab_focus_lost: false
  },

  init() {
    // Mouse movement
    document.addEventListener('mousemove', () => {
      this.data.mouse_move_count++;
    }, { passive: true });

    // Keyboard dynamics
    document.addEventListener('keydown', (e) => {
      const now = Date.now();
      if (this.data.last_keystroke_time > 0) {
        const interval = now - this.data.last_keystroke_time;
        // Ignore massive pauses
        if (interval < 5000) {
          this.data.keystroke_intervals.push(interval);
        }
      }
      this.data.last_keystroke_time = now;

      if (e.key === 'Backspace' || e.key === 'Delete') {
        this.data.backspace_count++;
      }
    });

    // Paste detection (Bots don't paste, humans do; or bots bypass typing entirely)
    const pwdInput = document.getElementById('password');
    if (pwdInput) {
      pwdInput.addEventListener('paste', () => {
        this.data.pasted_password = true;
      });
    }

    // Visibility (Did they background the tab?)
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') {
        this.data.tab_focus_lost = true;
      }
    });
  },

  finalize() {
    this.data.time_to_submit_s = (Date.now() - this.data.page_load_time) / 1000;
    
    // Calculate average keystroke interval
    let avg_interval = 0;
    if (this.data.keystroke_intervals.length > 0) {
      const sum = this.data.keystroke_intervals.reduce((a, b) => a + b, 0);
      avg_interval = sum / this.data.keystroke_intervals.length;
    }

    // Prepare packet for the ML Pipeline
    return {
      window_inner_width: window.innerWidth,
      window_inner_height: window.innerHeight,
      mouse_moved_before_click: this.data.mouse_move_count > 0 ? 1 : 0,
      time_to_submit_form_s: parseFloat(this.data.time_to_submit_s.toFixed(2)),
      keystroke_interval_ms: Math.round(avg_interval),
      backspace_count: this.data.backspace_count,
      pasted_password: this.data.pasted_password ? 1 : 0,
      tab_focus_lost: this.data.tab_focus_lost ? 1 : 0
    };
  }
};

// Start extraction
Telemetry.init();
