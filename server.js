const express = require("express");
const { corroborate } = require("./corroborate");

const app = express();
app.use(express.json());

app.post("/corroborate", (req, res) => {
  const result = corroborate(req.body);
  res.status(200).json(result);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Corroboration engine listening on port ${PORT}`);
});
