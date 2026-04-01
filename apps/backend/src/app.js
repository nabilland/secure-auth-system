require("dotenv").config();
const express = require("express");
const app = express();
const authRoutes = require("./routes/authRoutes");
const cors = require("cors");;

app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));
app.use("/auth", authRoutes);

app.get("/", (req, res) => {
  res.json({ message: "Backend is running!" });
});
app.get("/protected", (req, res) => {
  res.json({ message: "Protected data", user: req.user });
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});