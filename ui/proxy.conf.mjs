// `npm start` against a node: SPAREWALL_NODE=https://192.0.2.1 npm start.
// The node's certificate is usually self-signed, so it is not checked.
const target = process.env.SPAREWALL_NODE ?? 'https://localhost:8443';

export default {
  '/call': { target, secure: false, changeOrigin: true },
  '/openapi.json': { target, secure: false, changeOrigin: true },
};
