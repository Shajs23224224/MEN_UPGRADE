class AuthModal {
  constructor() {
    this.isOpen = false;
    this.currentTab = 'login'; // 'login' or 'register'
    this.recaptchaSiteKey = 'YOUR_RECAPTCHA_SITE_KEY'; // Replace with your reCAPTCHA site key
    
    this.init();
  }
  
  init() {
    this.createModal();
    this.setupEventListeners();
    this.loadRecaptcha();
  }
  
  createModal() {
    // Create modal container
    this.modal = document.createElement('div');
    this.modal.className = 'auth-modal';
    this.modal.setAttribute('role', 'dialog');
    this.modal.setAttribute('aria-labelledby', 'auth-modal-title');
    this.modal.setAttribute('aria-modal', 'true');
    
    // Create modal content
    this.modal.innerHTML = `
      <div class="auth-modal-content">
        <button class="auth-close-button" aria-label="Cerrar">&times;</button>
        
        <div class="auth-tabs">
          <button class="auth-tab ${this.currentTab === 'login' ? 'active' : ''}" 
                  data-tab="login" 
                  id="login-tab" 
                  aria-selected="${this.currentTab === 'login'}" 
                  aria-controls="login-panel">
            Iniciar Sesión
          </button>
          <button class="auth-tab ${this.currentTab === 'register' ? 'active' : ''}" 
                  data-tab="register" 
                  id="register-tab" 
                  aria-selected="${this.currentTab === 'register'}" 
                  aria-controls="register-panel">
            Registrarse
          </button>
        </div>
        
        <div class="auth-panels">
          <!-- Login Panel -->
          <div id="login-panel" 
               class="auth-panel ${this.currentTab === 'login' ? 'active' : ''}" 
               role="tabpanel" 
               aria-labelledby="login-tab"
               ${this.currentTab !== 'login' ? 'hidden' : ''}>
            
            <form id="login-form" class="auth-form">
              <div class="form-group">
                <label for="login-email">Correo Electrónico</label>
                <input type="email" id="login-email" name="email" required 
                       autocomplete="email" 
                       aria-required="true"
                       class="form-control">
                <div class="error-message" id="login-email-error"></div>
              </div>
              
              <div class="form-group">
                <div class="password-header">
                  <label for="login-password">Contraseña</label>
                  <a href="#" class="forgot-password" id="forgot-password-link">¿Olvidaste tu contraseña?</a>
                </div>
                <div class="password-input-container">
                  <input type="password" id="login-password" name="password" required 
                         autocomplete="current-password" 
                         aria-required="true"
                         class="form-control">
                  <button type="button" class="toggle-password" aria-label="Mostrar contraseña">
                    <i class="fas fa-eye"></i>
                  </button>
                </div>
                <div class="error-message" id="login-password-error"></div>
              </div>
              
              <div class="form-group remember-me">
                <input type="checkbox" id="remember-me" name="remember">
                <label for="remember-me">Recordarme</label>
              </div>
              
              <div id="recaptcha-container-login" class="recaptcha-container"></div>
              
              <button type="submit" class="auth-submit-button">Iniciar Sesión</button>
              
              <div class="social-login-divider">
                <span>o inicia sesión con</span>
              </div>
              
              <div class="social-login-buttons">
                <button type="button" class="social-login-button google" aria-label="Iniciar sesión con Google">
                  <i class="fab fa-google"></i>
                </button>
                <button type="button" class="social-login-button facebook" aria-label="Iniciar sesión con Facebook">
                  <i class="fab fa-facebook-f"></i>
                </button>
              </div>
              
              <div class="mfa-container" id="mfa-container" style="display: none;">
                <h3>Verificación en dos pasos</h3>
                <p>Ingresa el código de verificación enviado a tu autenticador o teléfono</p>
                <div class="form-group">
                  <input type="text" id="mfa-code" name="mfa_code" 
                         class="form-control" 
                         placeholder="Código de 6 dígitos"
                         maxlength="6"
                         pattern="\d{6}"
                         inputmode="numeric">
                  <div class="error-message" id="mfa-error"></div>
                </div>
                <button type="button" id="verify-mfa" class="auth-submit-button">Verificar</button>
                <button type="button" id="cancel-mfa" class="auth-cancel-button">Cancelar</button>
              </div>
              
              <div class="auth-footer">
                ¿No tienes una cuenta? <a href="#" class="switch-tab" data-tab="register">Regístrate</a>
              </div>
            </form>
          </div>
          
          <!-- Register Panel -->
          <div id="register-panel" 
               class="auth-panel ${this.currentTab === 'register' ? 'active' : ''}" 
               role="tabpanel" 
               aria-labelledby="register-tab"
               ${this.currentTab !== 'register' ? 'hidden' : ''}>
            
            <form id="register-form" class="auth-form">
              <div class="form-group">
                <label for="register-name">Nombre Completo</label>
                <input type="text" id="register-name" name="name" required 
                       autocomplete="name" 
                       aria-required="true"
                       class="form-control">
                <div class="error-message" id="register-name-error"></div>
              </div>
              
              <div class="form-group">
                <label for="register-email">Correo Electrónico</label>
                <input type="email" id="register-email" name="email" required 
                       autocomplete="email" 
                       aria-required="true"
                       class="form-control">
                <div class="error-message" id="register-email-error"></div>
              </div>
              
              <div class="form-group">
                <label for="register-phone">Teléfono (Opcional)</label>
                <input type="tel" id="register-phone" name="phone" 
                       autocomplete="tel" 
                       class="form-control"
                       placeholder="+57 300 123 4567">
                <div class="error-message" id="register-phone-error"></div>
              </div>
              
              <div class="form-group">
                <label for="register-password">Contraseña</label>
                <div class="password-input-container">
                  <input type="password" id="register-password" name="password" required 
                         autocomplete="new-password" 
                         aria-required="true"
                         class="form-control"
                         minlength="8">
                  <button type="button" class="toggle-password" aria-label="Mostrar contraseña">
                    <i class="fas fa-eye"></i>
                  </button>
                </div>
                <div class="password-requirements">
                  <p>La contraseña debe contener al menos:</p>
                  <ul>
                    <li id="req-length" class="invalid">8 caracteres</li>
                    <li id="req-uppercase" class="invalid">1 letra mayúscula</li>
                    <li id="req-number" class="invalid">1 número</li>
                    <li id="req-special" class="invalid">1 carácter especial</li>
                  </ul>
                </div>
                <div class="error-message" id="register-password-error"></div>
              </div>
              
              <div class="form-group">
                <label for="register-confirm-password">Confirmar Contraseña</label>
                <div class="password-input-container">
                  <input type="password" id="register-confirm-password" name="confirm_password" required 
                         autocomplete="new-password" 
                         aria-required="true"
                         class="form-control">
                  <button type="button" class="toggle-password" aria-label="Mostrar contraseña">
                    <i class="fas fa-eye"></i>
                  </button>
                </div>
                <div class="error-message" id="register-confirm-password-error"></div>
              </div>
              
              <div class="form-group terms-checkbox">
                <input type="checkbox" id="terms" name="terms" required aria-required="true">
                <label for="terms">
                  Acepto los <a href="/terminos" target="_blank">Términos de Servicio</a> y la 
                  <a href="/privacidad" target="_blank">Política de Privacidad</a> de MEJORA_MASCULINA
                </label>
                <div class="error-message" id="terms-error"></div>
              </div>
              
              <div id="recaptcha-container-register" class="recaptcha-container"></div>
              
              <button type="submit" class="auth-submit-button" id="register-submit">Crear Cuenta</button>
              
              <div class="auth-footer">
                ¿Ya tienes una cuenta? <a href="#" class="switch-tab" data-tab="login">Inicia Sesión</a>
              </div>
            </form>
          </div>
        </div>
      </div>
    `;
    
    // Add to body
    document.body.appendChild(this.modal);
    
    // Store references to important elements
    this.elements = {
      modal: this.modal,
      closeButton: this.modal.querySelector('.auth-close-button'),
      tabs: {
        login: document.getElementById('login-tab'),
        register: document.getElementById('register-tab')
      },
      panels: {
        login: document.getElementById('login-panel'),
        register: document.getElementById('register-panel')
      },
      forms: {
        login: document.getElementById('login-form'),
        register: document.getElementById('register-form')
      },
      mfaContainer: document.getElementById('mfa-container'),
      mfaCodeInput: document.getElementById('mfa-code'),
      verifyMfaButton: document.getElementById('verify-mfa'),
      cancelMfaButton: document.getElementById('cancel-mfa'),
      forgotPasswordLink: document.getElementById('forgot-password-link')
    };
    
    // Initialize password visibility toggles
    this.initPasswordToggles();
    
    // Initialize password strength checker
    this.initPasswordStrengthChecker();
  }
  
  setupEventListeners() {
    // Close modal when clicking the close button or outside the modal
    this.elements.closeButton.addEventListener('click', () => this.close());
    this.modal.addEventListener('click', (e) => {
      if (e.target === this.modal) {
        this.close();
      }
    });
    
    // Close with Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.isOpen) {
        this.close();
      }
    });
    
    // Tab switching
    Object.values(this.elements.tabs).forEach(tab => {
      tab.addEventListener('click', (e) => {
        e.preventDefault();
        const tabId = tab.getAttribute('data-tab');
        this.switchTab(tabId);
      });
    });
    
    // Switch tab links
    document.querySelectorAll('.switch-tab').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const tabId = link.getAttribute('data-tab');
        this.switchTab(tabId);
      });
    });
    
    // Form submissions
    if (this.elements.forms.login) {
      this.elements.forms.login.addEventListener('submit', (e) => this.handleLogin(e));
    }
    
    if (this.elements.forms.register) {
      this.elements.forms.register.addEventListener('submit', (e) => this.handleRegister(e));
    }
    
    // MFA verification
    if (this.elements.verifyMfaButton) {
      this.elements.verifyMfaButton.addEventListener('click', () => this.verifyMfa());
    }
    
    if (this.elements.cancelMfaButton) {
      this.elements.cancelMfaButton.addEventListener('click', () => this.cancelMfa());
    }
    
    // Forgot password
    if (this.elements.forgotPasswordLink) {
      this.elements.forgotPasswordLink.addEventListener('click', (e) => {
        e.preventDefault();
        this.showForgotPassword();
      });
    }
  }
  
  initPasswordToggles() {
    document.querySelectorAll('.toggle-password').forEach(button => {
      button.addEventListener('click', (e) => {
        const input = button.previousElementSibling;
        const isPassword = input.type === 'password';
        
        input.type = isPassword ? 'text' : 'password';
        button.setAttribute('aria-label', isPassword ? 'Ocultar contraseña' : 'Mostrar contraseña');
        button.innerHTML = isPassword ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
      });
    });
  }
  
  initPasswordStrengthChecker() {
    const passwordInput = document.getElementById('register-password');
    if (!passwordInput) return;
    
    passwordInput.addEventListener('input', () => {
      const password = passwordInput.value;
      const hasMinLength = password.length >= 8;
      const hasUppercase = /[A-Z]/.test(password);
      const hasNumber = /[0-9]/.test(password);
      const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
      
      // Update requirement indicators
      document.getElementById('req-length').classList.toggle('valid', hasMinLength);
      document.getElementById('req-uppercase').classList.toggle('valid', hasUppercase);
      document.getElementById('req-number').classList.toggle('valid', hasNumber);
      document.getElementById('req-special').classList.toggle('valid', hasSpecial);
      
      // Update password strength meter if exists
      const strengthMeter = document.querySelector('.password-strength-meter');
      if (strengthMeter) {
        const strength = [hasMinLength, hasUppercase, hasNumber, hasSpecial].filter(Boolean).length;
        strengthMeter.style.width = `${(strength / 4) * 100}%`;
        
        // Update strength text
        const strengthText = document.querySelector('.password-strength-text');
        if (strengthText) {
          const strengthLabels = ['Muy débil', 'Débil', 'Moderada', 'Fuerte'];
          strengthText.textContent = strengthLabels[strength - 1] || '';
          
          // Update strength class
          strengthText.className = 'password-strength-text ';
          if (strength <= 1) strengthText.className += 'strength-weak';
          else if (strength === 2) strengthText.className += 'strength-medium';
          else strengthText.className += 'strength-strong';
        }
      }
    });
  }
  
  loadRecaptcha() {
    // Load reCAPTCHA script if not already loaded
    if (window.grecaptcha) {
      this.renderRecaptcha();
    } else {
      const script = document.createElement('script');
      script.src = `https://www.google.com/recaptcha/api.js?render=${this.recaptchaSiteKey}`;
      script.async = true;
      script.defer = true;
      script.onload = () => this.renderRecaptcha();
      document.head.appendChild(script);
    }
  }
  
  renderRecaptcha() {
    // Render reCAPTCHA for login form
    if (document.getElementById('recaptcha-container-login')) {
      grecaptcha.ready(() => {
        grecaptcha.render('recaptcha-container-login', {
          sitekey: this.recaptchaSiteKey,
          size: 'invisible',
          callback: (token) => this.handleRecaptchaSuccess('login', token)
        });
      });
    }
    
    // Render reCAPTCHA for register form
    if (document.getElementById('recaptcha-container-register')) {
      grecaptcha.ready(() => {
        grecaptcha.render('recaptcha-container-register', {
          sitekey: this.recaptchaSiteKey,
          size: 'invisible',
          callback: (token) => this.handleRecaptchaSuccess('register', token)
        });
      });
    }
  }
  
  handleRecaptchaSuccess(formType, token) {
    // Handle reCAPTCHA success
    if (formType === 'login') {
      this.submitLoginForm(token);
    } else if (formType === 'register') {
      this.submitRegisterForm(token);
    }
  }
  
  async handleLogin(e) {
    e.preventDefault();
    
    // Reset error messages
    this.clearErrors('login');
    
    // Validate form
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const remember = document.getElementById('remember-me').checked;
    
    let isValid = true;
    
    if (!email) {
      this.showError('login-email', 'Por favor ingresa tu correo electrónico');
      isValid = false;
    } else if (!this.isValidEmail(email)) {
      this.showError('login-email', 'Por favor ingresa un correo electrónico válido');
      isValid = false;
    }
    
    if (!password) {
      this.showError('login-password', 'Por favor ingresa tu contraseña');
      isValid = false;
    }
    
    if (!isValid) return;
    
    // Show loading state
    this.setFormLoading('login', true);
    
    // Execute reCAPTCHA
    try {
      await grecaptcha.execute(this.recaptchaSiteKey, { action: 'login' });
    } catch (error) {
      console.error('reCAPTCHA error:', error);
      this.setFormLoading('login', false);
      this.showError('login', 'Error al verificar reCAPTCHA. Por favor intenta de nuevo.');
    }
  }
  
  async submitLoginForm(recaptchaToken) {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const remember = document.getElementById('remember-me').checked;
    
    try {
      // In a real app, you would make an API call to your backend
      // const response = await fetch('/api/auth/login', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ email, password, remember, recaptchaToken })
      // });
      // const data = await response.json();
      
      // For demo purposes, we'll simulate a successful login
      // In a real app, you would handle the response from your server
      console.log('Login attempt with:', { email, remember, recaptchaToken });
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Check if MFA is required (simulated)
      const requiresMfa = Math.random() > 0.5; // 50% chance for demo
      
      if (requiresMfa) {
        this.showMfaPrompt();
      } else {
        // Login successful
        this.handleLoginSuccess({
          user: { id: '123', name: 'Usuario Demo', email },
          token: 'demo-jwt-token',
          refreshToken: 'demo-refresh-token'
        });
      }
    } catch (error) {
      console.error('Login error:', error);
      this.showError('login', 'Error al iniciar sesión. Por favor verifica tus credenciales e intenta de nuevo.');
    } finally {
      this.setFormLoading('login', false);
    }
  }
  
  async handleRegister(e) {
    e.preventDefault();
    
    // Reset error messages
    this.clearErrors('register');
    
    // Get form values
    const name = document.getElementById('register-name').value.trim();
    const email = document.getElementById('register-email').value.trim();
    const phone = document.getElementById('register-phone').value.trim();
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;
    const terms = document.getElementById('terms').checked;
    
    // Validate form
    let isValid = true;
    
    if (!name) {
      this.showError('register-name', 'Por favor ingresa tu nombre completo');
      isValid = false;
    }
    
    if (!email) {
      this.showError('register-email', 'Por favor ingresa tu correo electrónico');
      isValid = false;
    } else if (!this.isValidEmail(email)) {
      this.showError('register-email', 'Por favor ingresa un correo electrónico válido');
      isValid = false;
    }
    
    if (phone && !this.isValidPhone(phone)) {
      this.showError('register-phone', 'Por favor ingresa un número de teléfono válido');
      isValid = false;
    }
    
    if (!password) {
      this.showError('register-password', 'Por favor ingresa una contraseña');
      isValid = false;
    } else if (password.length < 8) {
      this.showError('register-password', 'La contraseña debe tener al menos 8 caracteres');
      isValid = false;
    } else if (password !== confirmPassword) {
      this.showError('register-confirm-password', 'Las contraseñas no coinciden');
      isValid = false;
    }
    
    if (!terms) {
      this.showError('terms', 'Debes aceptar los términos y condiciones para continuar');
      isValid = false;
    }
    
    if (!isValid) return;
    
    // Show loading state
    this.setFormLoading('register', true);
    
    // Execute reCAPTCHA
    try {
      await grecaptcha.execute(this.recaptchaSiteKey, { action: 'register' });
    } catch (error) {
      console.error('reCAPTCHA error:', error);
      this.setFormLoading('register', false);
      this.showError('register', 'Error al verificar reCAPTCHA. Por favor intenta de nuevo.');
    }
  }
  
  async submitRegisterForm(recaptchaToken) {
    const name = document.getElementById('register-name').value.trim();
    const email = document.getElementById('register-email').value.trim();
    const phone = document.getElementById('register-phone').value.trim();
    const password = document.getElementById('register-password').value;
    
    try {
      // In a real app, you would make an API call to your backend
      // const response = await fetch('/api/auth/register', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ name, email, phone, password, recaptchaToken })
      // });
      // const data = await response.json();
      
      // For demo purposes, we'll simulate a successful registration
      console.log('Registration attempt with:', { name, email, phone, recaptchaToken });
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Show success message and switch to login
      this.showSuccessMessage('¡Registro exitoso! Por favor verifica tu correo electrónico para activar tu cuenta.');
      this.switchTab('login');
      
      // In a real app, you would redirect to a verification page or show a verification modal
    } catch (error) {
      console.error('Registration error:', error);
      this.showError('register', 'Error al registrar la cuenta. Por favor intenta de nuevo.');
    } finally {
      this.setFormLoading('register', false);
    }
  }
  
  showMfaPrompt() {
    // Show MFA input
    this.elements.mfaContainer.style.display = 'block';
    
    // Focus on MFA input
    setTimeout(() => {
      this.elements.mfaCodeInput.focus();
    }, 100);
    
    // In a real app, you would send the MFA code to the user's email/phone
    console.log('MFA required. Code would be sent to the user.');
  }
  
  async verifyMfa() {
    const code = this.elements.mfaCodeInput.value.trim();
    
    if (!code || code.length !== 6) {
      this.showError('mfa', 'Por favor ingresa un código de 6 dígitos');
      return;
    }
    
    // Show loading state
    this.elements.verifyMfaButton.disabled = true;
    this.elements.verifyMfaButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verificando...';
    
    try {
      // In a real app, you would verify the MFA code with your backend
      // const response = await fetch('/api/auth/verify-mfa', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ code })
      // });
      // const data = await response.json();
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // For demo, always accept '123456' as valid
      if (code === '123456') {
        // MFA verification successful
        this.handleLoginSuccess({
          user: { 
            id: '123', 
            name: 'Usuario Demo', 
            email: document.getElementById('login-email').value.trim() 
          },
          token: 'demo-jwt-token',
          refreshToken: 'demo-refresh-token'
        });
      } else {
        throw new Error('Código inválido');
      }
    } catch (error) {
      console.error('MFA verification error:', error);
      this.showError('mfa', 'Código inválido. Por favor intenta de nuevo.');
      this.elements.mfaCodeInput.focus();
    } finally {
      this.elements.verifyMfaButton.disabled = false;
      this.elements.verifyMfaButton.textContent = 'Verificar';
    }
  }
  
  cancelMfa() {
    // Hide MFA container
    this.elements.mfaContainer.style.display = 'none';
    
    // Clear MFA input
    this.elements.mfaCodeInput.value = '';
    
    // Reset form
    this.clearErrors('login');
    this.setFormLoading('login', false);
  }
  
  showForgotPassword() {
    // In a real app, you would show a forgot password form or redirect
    alert('Por favor ingresa tu correo electrónico para restablecer tu contraseña.');
    // You would implement a forgot password flow here
  }
  
  handleLoginSuccess(data) {
    // Save tokens (in a real app, you would use httpOnly cookies for refresh tokens)
    if (data.token) {
      localStorage.setItem('auth_token', data.token);
    }
    
    if (data.refreshToken) {
      // In a real app, you would set an httpOnly cookie for the refresh token
      document.cookie = `refresh_token=${data.refreshToken}; Path=/; Secure; SameSite=Strict`;
    }
    
    // Save user data
    if (data.user) {
      localStorage.setItem('user', JSON.stringify(data.user));
    }
    
    // Show success message
    this.showSuccessMessage(`¡Bienvenido de nuevo, ${data.user.name || 'Usuario'}!`);
    
    // Close modal after a short delay
    setTimeout(() => {
      this.close();
      
      // In a real app, you would redirect or refresh the page
      // window.location.href = '/dashboard';
      
      // Dispatch login event
      document.dispatchEvent(new CustomEvent('userLoggedIn', { detail: data.user }));
    }, 1000);
  }
  
  showError(fieldId, message) {
    if (fieldId === 'login' || fieldId === 'register') {
      // Show general form error
      const form = this.elements.forms[fieldId];
      const errorDiv = document.createElement('div');
      errorDiv.className = 'form-error-message';
      errorDiv.textContent = message;
      
      const firstChild = form.firstElementChild;
      if (firstChild) {
        form.insertBefore(errorDiv, firstChild);
      } else {
        form.appendChild(errorDiv);
      }
      
      // Auto-remove after 5 seconds
      setTimeout(() => {
        errorDiv.remove();
      }, 5000);
    } else if (fieldId === 'mfa') {
      // Show MFA error
      const errorDiv = document.getElementById('mfa-error');
      if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
      }
    } else {
      // Show field-specific error
      const errorDiv = document.getElementById(`${fieldId}-error`);
      if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
      }
      
      // Focus on the field with error
      const input = document.getElementById(fieldId);
      if (input) {
        input.focus();
        input.classList.add('error');
      }
    }
  }
  
  clearErrors(formType) {
    // Clear all error messages
    if (formType === 'login' || formType === 'register') {
      const form = this.elements.forms[formType];
      form.querySelectorAll('.error-message, .form-error-message').forEach(el => {
        el.textContent = '';
        el.style.display = 'none';
      });
      
      // Remove error classes from inputs
      form.querySelectorAll('.form-control.error').forEach(input => {
        input.classList.remove('error');
      });
    } else if (formType === 'mfa') {
      const errorDiv = document.getElementById('mfa-error');
      if (errorDiv) {
        errorDiv.textContent = '';
        errorDiv.style.display = 'none';
      }
    }
  }
  
  setFormLoading(formType, isLoading) {
    const form = this.elements.forms[formType];
    if (!form) return;
    
    const submitButton = form.querySelector('button[type="submit"]');
    if (!submitButton) return;
    
    if (isLoading) {
      submitButton.disabled = true;
      submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';
      
      // Disable all inputs
      form.querySelectorAll('input, button').forEach(input => {
        input.disabled = true;
      });
    } else {
      submitButton.disabled = false;
      submitButton.innerHTML = formType === 'login' ? 'Iniciar Sesión' : 'Crear Cuenta';
      
      // Enable all inputs
      form.querySelectorAll('input, button').forEach(input => {
        input.disabled = false;
      });
    }
  }
  
  showSuccessMessage(message) {
    // Create success message element
    const successDiv = document.createElement('div');
    successDiv.className = 'auth-success-message';
    successDiv.innerHTML = `
      <div class="success-icon">
        <i class="fas fa-check-circle"></i>
      </div>
      <div class="success-text">${message}</div>
    `;
    
    // Add to modal
    this.modal.querySelector('.auth-modal-content').insertBefore(
      successDiv,
      this.modal.querySelector('.auth-tabs')
    );
    
    // Remove after 5 seconds
    setTimeout(() => {
      successDiv.style.opacity = '0';
      setTimeout(() => successDiv.remove(), 300);
    }, 5000);
  }
  
  switchTab(tabId) {
    if (tabId !== 'login' && tabId !== 'register') return;
    
    // Update active tab
    Object.entries(this.elements.tabs).forEach(([id, tab]) => {
      if (id === tabId) {
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');
      } else {
        tab.classList.remove('active');
        tab.setAttribute('aria-selected', 'false');
      }
    });
    
    // Update active panel
    Object.entries(this.elements.panels).forEach(([id, panel]) => {
      if (id === `${tabId}-panel`) {
        panel.classList.add('active');
        panel.removeAttribute('hidden');
        
        // Focus on first input when panel becomes active
        const firstInput = panel.querySelector('input');
        if (firstInput) {
          setTimeout(() => firstInput.focus(), 100);
        }
      } else {
        panel.classList.remove('active');
        panel.setAttribute('hidden', 'true');
      }
    });
    
    // Update current tab
    this.currentTab = tabId;
    
    // Clear any errors
    this.clearErrors(tabId);
  }
  
  open(tab = 'login') {
    if (this.isOpen) return;
    
    this.isOpen = true;
    document.body.style.overflow = 'hidden';
    this.modal.style.display = 'flex';
    
    // Switch to the specified tab
    this.switchTab(tab);
    
    // Trigger reflow to enable CSS transitions
    this.modal.offsetHeight;
    
    // Add visible class for animations
    this.modal.classList.add('visible');
    
    // Focus on first input
    setTimeout(() => {
      const activePanel = this.modal.querySelector('.auth-panel.active');
      if (activePanel) {
        const firstInput = activePanel.querySelector('input');
        if (firstInput) firstInput.focus();
      }
    }, 100);
  }
  
  close() {
    if (!this.isOpen) return;
    
    this.isOpen = false;
    document.body.style.overflow = '';
    
    // Remove visible class for animations
    this.modal.classList.remove('visible');
    
    // Wait for animation to complete before hiding
    setTimeout(() => {
      if (!this.isOpen) {
        this.modal.style.display = 'none';
      }
    }, 300);
    
    // Clear forms when closing
    this.clearForms();
  }
  
  clearForms() {
    // Clear login form
    if (this.elements.forms.login) {
      this.elements.forms.login.reset();
      this.clearErrors('login');
    }
    
    // Clear register form
    if (this.elements.forms.register) {
      this.elements.forms.register.reset();
      this.clearErrors('register');
      
      // Reset password strength indicators
      const indicators = ['length', 'uppercase', 'number', 'special'];
      indicators.forEach(id => {
        const el = document.getElementById(`req-${id}`);
        if (el) el.className = 'invalid';
      });
    }
    
    // Hide MFA container
    if (this.elements.mfaContainer) {
      this.elements.mfaContainer.style.display = 'none';
      this.elements.mfaCodeInput.value = '';
    }
  }
  
  // Helper methods
  isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }
  
  isValidPhone(phone) {
    // Simple phone validation - adjust as needed
    const re = /^[+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,3}[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,4}$/;
    return re.test(phone);
  }
  
  // Static method to check if user is authenticated
  static isAuthenticated() {
    // In a real app, you would validate the token with your backend
    return !!localStorage.getItem('auth_token');
  }
  
  // Static method to get current user
  static getCurrentUser() {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  }
  
  // Static method to logout
  static logout() {
    // In a real app, you would call your backend to invalidate the token
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    
    // Clear refresh token cookie
    document.cookie = 'refresh_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    
    // Dispatch logout event
    document.dispatchEvent(new Event('userLoggedOut'));
    
    // Reload the page to update the UI
    window.location.reload();
  }
}

// Auto-initialize if this is the main module
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthModal;
} else {
  // Make AuthModal globally available
  window.AuthModal = AuthModal;
  
  // Auto-initialize if data-auth attribute is present
  document.addEventListener('DOMContentLoaded', () => {
    const authElements = document.querySelectorAll('[data-auth]');
    if (authElements.length > 0) {
      window.authModal = new AuthModal();
      
      // Add click handlers to all auth trigger elements
      authElements.forEach(element => {
        element.addEventListener('click', (e) => {
          e.preventDefault();
          const tab = element.getAttribute('data-auth') || 'login';
          window.authModal.open(tab);
        });
      });
    }
  });
}
