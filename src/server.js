const app = require("./app");
const config = require("./config");

const PORT = config.port;

app.listen(PORT, () => {
  console.log(`[SimpleAuthx] Server running on http://localhost:${PORT}`);
  console.log(`[SimpleAuthx] Environment: ${config.env}`);
});
