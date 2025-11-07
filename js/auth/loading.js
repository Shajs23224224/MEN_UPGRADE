class LoadingScreen {
  constructor(options = {}) {
    this.options = {
      container: document.body,
      showProgress: true,
      skipButtonText: 'Skip',
      minDisplayTime: 2000, // Minimum display time in ms
      ...options
    };
    
    this.isLoading = true;
    this.startTime = Date.now();
    this.assetsToLoad = [];
    this.assetsLoaded = 0;
    this.animationFrame = null;
    
    this.init();
  }
  
  init() {
    this.createLoadingScreen();
    this.loadAssets();
    this.setupEventListeners();
  }
  
  createLoadingScreen() {
    // Create loading screen container
    this.loadingScreen = document.createElement('div');
    this.loadingScreen.className = 'loading-screen';
    this.loadingScreen.setAttribute('role', 'status');
    this.loadingScreen.setAttribute('aria-live', 'polite');
    this.loadingScreen.setAttribute('aria-label', 'Loading application');
    
    // Add loading content
    this.loadingScreen.innerHTML = `
      <div class="loading-content">
        <div class="loading-animation">
          <div class="spinner"></div>
          <div class="lottie-container" id="lottie-loading"></div>
          <video class="loading-video" autoplay muted loop playsinline>
            <source src="assets/loading-animation.mp4" type="video/mp4">
            Your browser does not support the video tag.
          </video>
        </div>
        <div class="loading-text">
          <h2>MEJORA_MASCULINA</h2>
          <p>Cargando tu experiencia...</p>
        </div>
        <div class="loading-progress">
          <div class="progress-bar">
            <div class="progress" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
          </div>
          <div class="progress-text">0%</div>
        </div>
        <button class="skip-button" aria-label="Skip loading">${this.options.skipButtonText}</button>
      </div>
    `;
    
    // Add to DOM
    this.options.container.appendChild(this.loadingScreen);
    
    // Initialize Lottie if available
    this.initLottie();
  }
  
  initLottie() {
    if (typeof lottie !== 'undefined') {
      // Replace with your Lottie animation path
      this.lottieAnimation = lottie.loadAnimation({
        container: document.getElementById('lottie-loading'),
        renderer: 'svg',
        loop: true,
        autoplay: true,
        path: 'assets/loading-animation.json'
      });
    }
  }
  
  loadAssets() {
    // Add your critical assets here (CSS, JS, fonts, etc.)
    this.assetsToLoad = [
      // Add paths to your critical assets
      'css/auth.css',
      'js/auth/auth.js',
      'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css',
      'https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.9.6/lottie.min.js'
    ];
    
    // Load each asset
    this.assetsToLoad.forEach(asset => this.loadAsset(asset));
    
    // If no assets to load, complete immediately
    if (this.assetsToLoad.length === 0) {
      this.updateProgress(100);
    }
  }
  
  loadAsset(url) {
    return new Promise((resolve, reject) => {
      const extension = url.split('.').pop().split('?')[0];
      let element;
      
      switch(extension) {
        case 'css':
          element = document.createElement('link');
          element.rel = 'stylesheet';
          element.href = url;
          break;
        case 'js':
          element = document.createElement('script');
          element.src = url;
          element.async = false;
          break;
        default:
          // For other assets, we'll just count them as loaded
          this.assetLoaded();
          return resolve();
      }
      
      element.onload = () => {
        this.assetLoaded();
        resolve();
      };
      
      element.onerror = (error) => {
        console.error(`Error loading ${url}:`, error);
        this.assetLoaded();
        resolve(); // Continue even if some assets fail to load
      };
      
      document.head.appendChild(element);
    });
  }
  
  assetLoaded() {
    this.assetsLoaded++;
    const progress = Math.min(Math.round((this.assetsLoaded / this.assetsToLoad.length) * 100), 100);
    this.updateProgress(progress);
    
    if (this.assetsLoaded >= this.assetsToLoad.length) {
      this.allAssetsLoaded();
    }
  }
  
  updateProgress(percentage) {
    if (!this.options.showProgress) return;
    
    const progressBar = this.loadingScreen.querySelector('.progress');
    const progressText = this.loadingScreen.querySelector('.progress-text');
    
    if (progressBar) {
      progressBar.style.width = `${percentage}%`;
      progressBar.setAttribute('aria-valuenow', percentage);
    }
    
    if (progressText) {
      progressText.textContent = `${percentage}%`;
    }
  }
  
  allAssetsLoaded() {
    const elapsedTime = Date.now() - this.startTime;
    const remainingTime = Math.max(0, this.options.minDisplayTime - elapsedTime);
    
    // Wait for minimum display time to complete
    setTimeout(() => {
      this.complete();
    }, remainingTime);
  }
  
  setupEventListeners() {
    // Skip button
    const skipButton = this.loadingScreen.querySelector('.skip-button');
    if (skipButton) {
      skipButton.addEventListener('click', () => this.complete());
      
      // Make skip button keyboard accessible
      skipButton.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this.complete();
        }
      });
    }
    
    // Handle window load event as a fallback
    window.addEventListener('load', () => {
      if (this.isLoading) {
        this.allAssetsLoaded();
      }
    });
  }
  
  complete() {
    if (!this.isLoading) return;
    
    this.isLoading = false;
    
    // Clean up Lottie animation if it exists
    if (this.lottieAnimation) {
      this.lottieAnimation.destroy();
    }
    
    // Add fade-out animation
    this.loadingScreen.classList.add('fade-out');
    
    // Remove from DOM after animation completes
    setTimeout(() => {
      this.loadingScreen.remove();
      
      // Initialize auth modal after loading is complete
      if (typeof AuthModal !== 'undefined') {
        new AuthModal();
      } else {
        console.warn('AuthModal not found. Make sure auth.js is loaded.');
      }
    }, 500);
  }
}

// Auto-initialize if this is the main module
if (typeof module !== 'undefined' && module.exports) {
  module.exports = LoadingScreen;
} else {
  // Start loading screen when DOM is ready
  document.addEventListener('DOMContentLoaded', () => {
    window.loadingScreen = new LoadingScreen();
  });
}
