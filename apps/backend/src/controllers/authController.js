const prisma = require("../config/prisma");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// ===== REGISTER =====
exports.register = async (req, res) => {
  try {
    const email = req.body.email?.trim();
    const password = req.body.password;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      return res.status(401).json({ message: "Invalid email format" });
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    if (!password || !passwordRegex.test(password)) {
      return res.status(401).json({
        error:
          "Password must be at least 8 characters and include uppercase-lowercase letters",
      });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(401).json({ error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, password: hashedPassword },
    });

    res.json({
      message: "User created successfully",
      user: { id: user.id, email: user.email, createdAt: user.createdAt },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ===== LOGIN =====
exports.login = async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    if (user.failedLoginAttempt >= 3) {
      if (!captchaToken) {
        return res.status(403).json({ message: "Captcha required" });
      }
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid credentials" });

    // Generate access token
    const accessToken = jwt.sign({ userId: user.id }, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: "15m",
    });
    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" },
    );

    // Save refresh token in DB
    await prisma.user.update({
      where: { id: user.id },
      data: { refreshToken },
    });

    res.json({ message: "Login success", accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ===== REFRESH TOKEN =====
exports.refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(401);

    // Verify token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    // Find user with matching refresh token
    if (!user || user.refreshToken !== refreshToken) return res.sendStatus(403);

    // Generate new access token
    const newAccessToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" },
    );

    res.json({ accessToken: newAccessToken });
  } catch (error) {
    return res.sendStatus(403);
  }
};

// ===== LOGOUT =====
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(401);

    const user = await prisma.user.findFirst({ where: { refreshToken } });
    if (!user) return res.sendStatus(204);

    await prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: null },
    });

    res.sendStatus(204);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
