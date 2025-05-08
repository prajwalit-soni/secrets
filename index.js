require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const ejs = require('ejs');
const path = require('path');
const debug = require('debug')('app:auth');

const app = express();

// Database Connection
mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true
})
.then(() => debug('MongoDB connected successfully'))
.catch(err => {
  debug('MongoDB connection error:', err);
  process.exit(1);
});

// Middleware Stack
app.set('trust proxy', 1); 
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});

app.use(limiter);


// View Engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Global Template Variables
app.use((req, res, next) => {
  res.locals = {
    title: 'Secrets App',
    user: null,
    error: null,
    success: null
  };
  next();
});

// User Model
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true,
    lowercase: true,
    validate: [validator.isEmail, 'Invalid email']
  },
  password: { type: String, required: true, select: false },
  createdAt: { type: Date, default: Date.now }
}));

// Helper Functions
const hashPassword = async (password) => {
  return await bcrypt.hash(password, 10);
};

const comparePasswords = async (inputPassword, storedHash) => {
  return await bcrypt.compare(inputPassword, storedHash);
};

const generateToken = (user) => {
  return jwt.sign(
    { 
      userId: user._id,
      email: user.email
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
};

// Routes
app.get('/', (req, res) => {
  res.render('home', { title: 'Welcome' });
});

// Registration Routes
app.get('/register', (req, res) => {
  res.render('register', { title: 'Create Account' });
});

app.post('/register', async (req, res) => {
  try {
    let { name, email, password, confirmPassword } = req.body;
    
    // Sanitize inputs
    name = name.trim();
    email = email.trim().toLowerCase();
    password = password.trim();
    confirmPassword = confirmPassword.trim();

    // Validation
    const errors = [];
    if (!name) errors.push('Name is required');
    if (!validator.isEmail(email)) errors.push('Invalid email format');
    if (password !== confirmPassword) errors.push('Passwords do not match');
    if (!validator.isStrongPassword(password, {
      minLength: 6,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1
    })) {
      errors.push('Password must be 6+ chars with uppercase, lowercase, and number');
    }

    if (errors.length > 0) {
      return res.status(400).render('register', { 
        error: errors.join(', '),
        formData: { name, email }
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).render('register', {
        error: 'Email already in use',
        formData: { name, email }
      });
    }

    // Create new user
    const user = new User({
      name,
      email,
      password: await hashPassword(password)
    });

    await user.save();
    debug(`New user registered: ${email}`);
    
    res.redirect('/login?registered=true');

  } catch (err) {
    debug('Registration error:', err);
    res.status(500).render('register', {
      error: 'Registration failed. Please try again.'
    });
  }
});

// Login Routes
app.get('/login', (req, res) => {
  const success = req.query.registered ? 'Registration successful! Please login.' : null;
  res.render('login', { title: 'Login', success });
});

app.post('/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    email = email.trim().toLowerCase();
    password = password.trim();

    // Validate
    if (!email || !password) {
      return res.status(400).render('login', {
        error: 'Email and password are required'
      });
    }

    // Find user (including password field)
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      debug(`Login attempt failed for unknown email: ${email}`);
      return res.status(400).render('login', {
        error: 'Invalid credentials'
      });
    }

    // Compare passwords
    const isMatch = await comparePasswords(password, user.password);
    if (!isMatch) {
      debug(`Password mismatch for user: ${email}`);
      return res.status(400).render('login', {
        error: 'Invalid credentials'
      });
    }

    // Generate and set token
    const token = generateToken(user);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000,
      sameSite: 'strict'
    });

    debug(`User logged in: ${email}`);
    res.redirect('/secrets');

  } catch (err) {
    debug('Login error:', err);
    res.status(500).render('login', {
      error: 'Login failed. Please try again.'
    });
  }
});

// Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      debug('No auth token found');
      return res.redirect('/login');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      debug('Invalid user in token');
      return res.redirect('/login');
    }

    req.user = user;
    res.locals.user = user;
    next();
  } catch (err) {
    debug('Authentication error:', err);
    res.redirect('/login');
  }
};

// Protected Routes
app.get('/secrets', authenticate, (req, res) => {
  res.render('secrets', { title: 'Your Secrets' });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Error Handling
app.use((err, req, res, next) => {
  debug('Application error:', err);
  res.status(500).render('error', {
    title: 'Error',
    error: 'Something went wrong'
  });
});

// Server Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  debug(`Server running on port ${PORT}`);
});
