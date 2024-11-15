const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/Database', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Database connected'))
.catch(err => console.error('Error connecting to database:', err));

// Define User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Routes
app.get("/", (req, res) => {
  res.redirect('index.html');
});

// Registration Route with Validation and Password Hashing
app.post("/signup", async (req, res) => {
  const { name, email, phone, password } = req.body;

  // Check if all required fields are provided
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // Convert email to string explicitly
    const emailString = email.toString();

    // Check for existing user with the same email
    const existingUser = await User.findOne({ email: emailString });
    if (existingUser) {
      return res.status(400).json({ error: "Email already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, email: emailString, phone, password: hashedPassword });
    await newUser.save();

    console.log("Registered");
    res.json({ success: true, message: "Registration successful" });
  } catch (error) {  
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login Route with Password Validation
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare hashed password
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Send back user data for storing in local storage
    console.log("User logged in successfully");
    res.json({ 
      success: true, 
      message: "Login successful",
      user: { name: user.name, phone: user.phone, email: user.email } // Include user details here
    });
  } catch (error) {
    console.error("Error logging in user:", error);
    res.status(500).json({ message: "Error logging in. Please try again later." });
  }
});



app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});