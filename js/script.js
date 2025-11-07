// DOM Elements
const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
const navLinks = document.querySelector('.nav-links');
const modal = document.getElementById('serviceModal');
const closeModal = document.querySelector('.close-modal');
const modalContent = document.getElementById('modalContent');
const serviceButtons = document.querySelectorAll('.service-button');
const contactForm = document.getElementById('contactForm');
const newsletterForm = document.getElementById('newsletterForm');

// Sample services data - In a real app, this would come from a CMS or API
const services = [
    {
        id: 'coaching-1on1',
        title: 'Coaching 1 a 1',
        sku: 'COACH-001',
        price: 299,
        summary: 'Sesiones personalizadas de coaching para tu desarrollo personal',
        description: 'Sesiones individuales de coaching diseñadas para ayudarte a alcanzar tus metas personales y profesionales. Trabajaremos juntos para identificar obstáculos, establecer objetivos claros y crear un plan de acción efectivo.',
        features: [
            'Sesiones de 60 minutos vía Zoom',
            'Plan personalizado de desarrollo',
            'Soporte por correo electrónico entre sesiones',
            'Recursos y ejercicios personalizados',
            'Seguimiento de progreso'
        ],
        deliverables: [
            'Sesión inicial de evaluación',
            'Plan de acción personalizado',
            'Grabaciones de las sesiones',
            'Material complementario',
            'Informe de progreso mensual'
        ],
        duration: '3-6 meses (recomendado)',
        faq: [
            {
                question: '¿Cuánto tiempo duran las sesiones?',
                answer: 'Cada sesión tiene una duración de 60 minutos.'
            },
            {
                question: '¿Con qué frecuencia son las sesiones?',
                answer: 'Se recomienda una sesión por semana para mantener el impulso y el compromiso.'
            },
            {
                question: '¿Qué pasa si necesito cancelar una sesión?',
                answer: 'Puedes cancelar o reagendar con 24 horas de anticipación sin costo alguno.'
            }
        ],
        image: 'https://images.unsplash.com/photo-1522202176988-66273c2fd55f?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1471&q=80'
    },
    {
        id: 'programa-grupo',
        title: 'Programa en Grupo',
        sku: 'GROUP-001',
        price: 149,
        summary: 'Aprende y crece junto a otros hombres en un entorno de apoyo mutuo',
        description: 'Un programa grupal diseñado para el desarrollo personal masculino. Aprovecha el poder de la comunidad para crecer, compartir experiencias y aprender de las historias de otros.',
        features: [
            'Sesiones grupales semanales',
            'Comunidad privada',
            'Material exclusivo',
            'Sesiones de preguntas y respuestas',
            'Acceso a grabaciones'
        ],
        deliverables: [
            '8 sesiones grupales',
            'Acceso a la comunidad',
            'Guías y recursos',
            'Sesión de cierre individual'
        ],
        duration: '2 meses',
        faq: [
            {
                question: '¿Cuántas personas habrá en el grupo?',
                answer: 'Los grupos están limitados a un máximo de 10 participantes para garantizar la calidad de la experiencia.'
            },
            {
                question: '¿Qué pasa si me pierdo una sesión?',
                answer: 'Todas las sesiones se graban y estarán disponibles para los participantes.'
            }
        ],
        image: 'https://images.unsplash.com/photo-1529154691717-330d06194b0d?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1470&q=80'
    },
    {
        id: 'taller-presencial',
        title: 'Taller Presencial',
        sku: 'WORKSHOP-001',
        price: 199,
        summary: 'Experiencia intensiva de un día para transformar tu vida',
        description: 'Un taller transformador de un día completo donde trabajarás en tu desarrollo personal a través de ejercicios prácticos, dinámicas grupales y reflexiones profundas. Ideal para quienes buscan un impacto inmediato y poderoso en su vida.',
        features: [
            '8 horas de taller intensivo',
            'Material de trabajo',
            'Comida y refrigerios incluidos',
            'Sesión de seguimiento grupal',
            'Certificado de participación'
        ],
        deliverables: [
            'Manual del participante',
            'Acceso a recursos exclusivos',
            'Sesión de seguimiento',
            'Certificado de participación'
        ],
        duration: '1 día (8 horas)',
        faq: [
            {
                question: '¿Qué necesito llevar al taller?',
                answer: 'Solo necesitas ropa cómoda, cuaderno y pluma. Te proporcionaremos todo el material necesario.'
            },
            {
                question: '¿Hay estacionamiento disponible?',
                answer: 'Sí, hay estacionamiento gratuito en el lugar.'
            }
        ],
        image: 'https://images.unsplash.com/photo-1542744173-8e7e53415bb0?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1470&q=80'
    }
];

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    // Initialize mobile menu
    initMobileMenu();
    
    // Load services
    loadServices();
    
    // Initialize modals
    initModals();
    
    // Initialize forms
    initForms();
    
    // Smooth scrolling for anchor links
    initSmoothScrolling();
    
    // Initialize Stripe and PayPal
    initPaymentGateways();
    
    // Add animation on scroll
    initScrollAnimations();
});

// Mobile Menu Toggle
function initMobileMenu() {
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', function() {
            navLinks.classList.toggle('active');
            this.querySelector('i').classList.toggle('fa-bars');
            this.querySelector('i').classList.toggle('fa-times');
        });
    }
    
    // Close mobile menu when clicking on a link
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', () => {
            if (navLinks.classList.contains('active')) {
                navLinks.classList.remove('active');
                mobileMenuBtn.querySelector('i').classList.toggle('fa-bars');
                mobileMenuBtn.querySelector('i').classList.toggle('fa-times');
            }
        });
    });
}

// Load services into the page
function loadServices() {
    const servicesContainer = document.getElementById('services-container');
    
    if (!servicesContainer) return;
    
    services.forEach(service => {
        const serviceElement = document.createElement('div');
        serviceElement.className = 'service-card';
        serviceElement.innerHTML = `
            <div class="service-image">
                <img src="${service.image}" alt="${service.title}" loading="lazy">
            </div>
            <div class="service-content">
                <h3>${service.title}</h3>
                <p>${service.summary}</p>
                <div class="service-price">Desde $${service.price}</div>
                <ul class="service-features">
                    ${service.features.slice(0, 3).map(feature => `<li>${feature}</li>`).join('')}
                </ul>
                <button class="cta-button service-button" data-service="${service.id}">Ver más</button>
            </div>
        `;
        
        servicesContainer.appendChild(serviceElement);
    });
    
    // Add event listeners to service buttons
    document.querySelectorAll('.service-button').forEach(button => {
        button.addEventListener('click', function() {
            const serviceId = this.getAttribute('data-service');
            const service = services.find(s => s.id === serviceId);
            if (service) {
                openServiceModal(service);
            }
        });
    });
}

// Initialize modals
function initModals() {
    // Close modal when clicking the close button
    if (closeModal) {
        closeModal.addEventListener('click', function() {
            closeServiceModal();
        });
    }
    
    // Close modal when clicking outside the modal content
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            closeServiceModal();
        }
    });
    
    // Close modal with Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && modal.style.display === 'block') {
            closeServiceModal();
        }
    });
    
    // Privacy policy modal
    document.querySelectorAll('[data-modal]').forEach(element => {
        element.addEventListener('click', function(e) {
            e.preventDefault();
            const modalId = this.getAttribute('data-modal');
            if (modalId === 'privacy-policy') {
                openPrivacyPolicyModal();
            }
        });
    });
}

// Open service modal
function openServiceModal(service) {
    if (!modal || !modalContent) return;
    
    // Create FAQ HTML
    const faqHtml = service.faq ? `
        <div class="service-modal-faq">
            <h3>Preguntas Frecuentes</h3>
            <div class="faq-accordion">
                ${service.faq.map((item, index) => `
                    <div class="faq-item">
                        <button class="faq-question" aria-expanded="false" aria-controls="faq-${service.id}-${index}">
                            ${item.question}
                            <span class="faq-icon">+</span>
                        </button>
                        <div class="faq-answer" id="faq-${service.id}-${index}" hidden>
                            <p>${item.answer}</p>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    ` : '';
    
    // Set modal content
    modalContent.innerHTML = `
        <div class="service-modal-header">
            <h2>${service.title}</h2>
            <p>${service.summary}</p>
        </div>
        <div class="service-modal-content">
            <div class="service-description">
                <h3>Descripción</h3>
                <p>${service.description}</p>
            </div>
            
            <div class="service-modal-features">
                <h3>Lo que incluye</h3>
                <ul>
                    ${service.features.map(feature => `<li>${feature}</li>`).join('')}
                </ul>
            </div>
            
            <div class="service-deliverables">
                <h3>Entregables</h3>
                <ul>
                    ${service.deliverables.map(item => `<li>${item}</li>`).join('')}
                </ul>
            </div>
            
            <div class="service-duration">
                <h3>Duración</h3>
                <p>${service.duration}</p>
            </div>
            
            ${faqHtml}
            
            <div class="service-modal-cta">
                <button class="cta-button" onclick="initiateCheckout('${service.id}', 'reserve')">
                    Reservar ahora
                </button>
                <button class="cta-button secondary" onclick="initiateCheckout('${service.id}', 'purchase')">
                    Comprar ahora
                </button>
            </div>
        </div>
    `;
    
    // Show modal
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
    
    // Initialize FAQ accordion
    initFaqAccordion();
}

// Close service modal
function closeServiceModal() {
    if (!modal) return;
    
    modal.style.display = 'none';
    document.body.style.overflow = 'auto';
}

// Open privacy policy modal
function openPrivacyPolicyModal() {
    const modal = document.getElementById('privacy-policy');
    if (modal) {
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }
}

// Initialize FAQ accordion
function initFaqAccordion() {
    const faqQuestions = document.querySelectorAll('.faq-question');
    
    faqQuestions.forEach(question => {
        question.addEventListener('click', function() {
            const isExpanded = this.getAttribute('aria-expanded') === 'true';
            const answer = this.nextElementSibling;
            const icon = this.querySelector('.faq-icon');
            
            // Toggle the answer visibility
            this.setAttribute('aria-expanded', !isExpanded);
            answer.hidden = isExpanded;
            
            // Update the icon
            icon.textContent = isExpanded ? '+' : '-';
            
            // Close other open items
            if (!isExpanded) {
                faqQuestions.forEach(otherQuestion => {
                    if (otherQuestion !== question && otherQuestion.getAttribute('aria-expanded') === 'true') {
                        otherQuestion.setAttribute('aria-expanded', 'false');
                        otherQuestion.nextElementSibling.hidden = true;
                        otherQuestion.querySelector('.faq-icon').textContent = '+';
                    }
                });
            }
        });
    });
}

// Initialize forms
function initForms() {
    // Contact form
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Validate form
            const name = document.getElementById('name').value.trim();
            const email = document.getElementById('email').value.trim();
            const message = document.getElementById('message').value.trim();
            const privacyCheck = document.getElementById('privacy-check');
            
            if (!name || !email || !message) {
                showAlert('Por favor completa todos los campos', 'error');
                return;
            }
            
            if (!isValidEmail(email)) {
                showAlert('Por favor ingresa un correo electrónico válido', 'error');
                return;
            }
            
            if (!privacyCheck.checked) {
                showAlert('Debes aceptar la política de privacidad', 'error');
                return;
            }
            
            // In a real app, you would send this data to your server
            console.log('Form submitted:', { name, email, message });
            
            // Show success message
            showAlert('¡Mensaje enviado con éxito! Nos pondremos en contacto contigo pronto.', 'success');
            
            // Reset form
            contactForm.reset();
        });
    }
    
    // Newsletter form
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const email = this.querySelector('input[type="email"]').value.trim();
            
            if (!email) {
                showAlert('Por favor ingresa tu correo electrónico', 'error');
                return;
            }
            
            if (!isValidEmail(email)) {
                showAlert('Por favor ingresa un correo electrónico válido', 'error');
                return;
            }
            
            // In a real app, you would send this to your email marketing service
            console.log('Newsletter subscription:', email);
            
            // Show success message
            showAlert('¡Gracias por suscribirte! Pronto recibirás nuestras novedades.', 'success');
            
            // Reset form
            this.reset();
        });
    }
}

// Validate email
function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Show alert message
function showAlert(message, type = 'info') {
    // Remove any existing alerts
    const existingAlert = document.querySelector('.alert');
    if (existingAlert) {
        existingAlert.remove();
    }
    
    // Create alert element
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    
    // Add alert to the page
    document.body.appendChild(alert);
    
    // Show alert with animation
    setTimeout(() => {
        alert.classList.add('show');
    }, 10);
    
    // Remove alert after 5 seconds
    setTimeout(() => {
        alert.classList.remove('show');
        setTimeout(() => {
            alert.remove();
        }, 300);
    }, 5000);
}

// Initialize smooth scrolling
function initSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                const headerOffset = 100;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
                
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Initialize payment gateways
function initPaymentGateways() {
    // Initialize Stripe
    if (typeof Stripe !== 'undefined') {
        const stripe = Stripe('YOUR_STRIPE_PUBLIC_KEY');
        const elements = stripe.elements();
        
        // Create an instance of the card Element
        const card = elements.create('card');
        
        // Add an instance of the card Element into the `card-element` div
        const cardElement = document.getElementById('card-element');
        if (cardElement) {
            card.mount('#card-element');
            
            // Handle form submission
            const form = document.getElementById('stripe-payment-form');
            if (form) {
                form.addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    const {error, paymentMethod} = await stripe.createPaymentMethod({
                        type: 'card',
                        card: card,
                    });
                    
                    if (error) {
                        showAlert(error.message, 'error');
                    } else {
                        // Send paymentMethod.id to your server to complete the payment
                        console.log('PaymentMethod:', paymentMethod);
                        // In a real app, you would send this to your server
                        // and handle the payment confirmation
                    }
                });
            }
        }
    }
    
    // Initialize PayPal
    if (typeof paypal !== 'undefined') {
        paypal.Buttons({
            createOrder: function(data, actions) {
                // Set up the transaction
                return actions.order.create({
                    purchase_units: [{
                        amount: {
                            value: '0.01' // This should be dynamic based on the selected service
                        }
                    }]
                });
            },
            onApprove: function(data, actions) {
                // Capture the funds from the transaction
                return actions.order.capture().then(function(details) {
                    // Show a success message to your buyer
                    showAlert('¡Pago completado con éxito! ' + details.payer.name.given_name, 'success');
                    // In a real app, you would send this data to your server
                    console.log('Payment completed:', details);
                });
            },
            onError: function(err) {
                // Show an error page here, when an error occurs
                showAlert('Ocurrió un error al procesar el pago: ' + err, 'error');
            }
        }).render('#paypal-button-container');
    }
}

// Initialize checkout process
function initiateCheckout(serviceId, action) {
    const service = services.find(s => s.id === serviceId);
    if (!service) return;
    
    if (action === 'reserve') {
        // Open Calendly for reservation
        Calendly.initPopupWidget({
            url: '[CALENDLY_LINK]'
        });
    } else if (action === 'purchase') {
        // Show payment options
        document.getElementById('payment-forms').style.display = 'block';
        // In a real app, you would handle the payment process here
        // and redirect to the success URL after successful payment
        // window.location.href = '[PAYMENT_SUCCESS_URL]';
    }
}

// Initialize scroll animations
function initScrollAnimations() {
    const animateOnScroll = function() {
        const elements = document.querySelectorAll('.animate-on-scroll');
        
        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const screenPosition = window.innerHeight / 1.3;
            
            if (elementPosition < screenPosition) {
                element.classList.add('animated');
            }
        });
    };
    
    // Run once on page load
    animateOnScroll();
    
    // Run on scroll
    window.addEventListener('scroll', animateOnScroll);
}

// Add animation classes to elements
function addAnimationClasses() {
    // Add animation classes to sections
    const sections = document.querySelectorAll('section');
    sections.forEach((section, index) => {
        section.classList.add('animate-on-scroll');
        section.style.opacity = '0';
        section.style.transform = 'translateY(20px)';
        section.style.transition = `opacity 0.6s ease-out ${index * 0.2}s, transform 0.6s ease-out ${index * 0.2}s`;
    });
    
    // Add animation classes to service cards
    const serviceCards = document.querySelectorAll('.service-card');
    serviceCards.forEach((card, index) => {
        card.classList.add('animate-on-scroll');
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = `opacity 0.6s ease-out ${0.3 + (index * 0.1)}s, transform 0.6s ease-out ${0.3 + (index * 0.1)}s`;
    });
}

// Call this function when the page loads
window.addEventListener('load', function() {
    addAnimationClasses();
    
    // Trigger animations after a short delay to ensure the page is fully loaded
    setTimeout(initScrollAnimations, 500);
});

// Add CSS for animations
const style = document.createElement('style');
style.textContent = `
    .animate-on-scroll.animated {
        opacity: 1 !important;
        transform: translateY(0) !important;
    }
    
    .alert {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        border-radius: 5px;
        color: white;
        font-weight: 500;
        z-index: 1000;
        opacity: 0;
        transform: translateX(100%);
        transition: opacity 0.3s ease, transform 0.3s ease;
        max-width: 400px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }
    
    .alert.show {
        opacity: 1;
        transform: translateX(0);
    }
    
    .alert-success {
        background-color: #4caf50;
    }
    
    .alert-error {
        background-color: #f44336;
    }
    
    .alert-info {
        background-color: #2196f3;
    }
    
    .faq-question {
        width: 100%;
        text-align: left;
        background: none;
        border: none;
        padding: 15px 0;
        font-size: 1rem;
        font-weight: 600;
        color: var(--primary-color);
        border-bottom: 1px solid #eee;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .faq-answer {
        padding: 15px 0;
        border-bottom: 1px solid #eee;
    }
    
    .faq-item:last-child .faq-question,
    .faq-item:last-child .faq-answer {
        border-bottom: none;
    }
    
    .faq-icon {
        font-size: 1.5rem;
        font-weight: 700;
        transition: transform 0.3s ease;
    }
    
    [aria-expanded="true"] .faq-icon {
        transform: rotate(45deg);
    }
`;

document.head.appendChild(style);
