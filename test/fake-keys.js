// Fake but pattern-valid credentials, assembled at runtime so this repository never contains a
// literal secret-looking string (keeps GitHub push protection and secret scanners quiet).
const rep = (s, n) => s.repeat(n);
const j = (...p) => p.join('');
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
export const FAKE = {
  awsId: j('AK', 'IA', 'FAKE', 'EXAMPLE', '12345'),            // AKIA + 16
  awsSecret: j('wJal', 'rXUt', 'nFEMI', '/K7MDENG', '/bPxRfiCY', 'FAKEFAKEKE'), // 40
  stripeLive: j('sk', '_live_', rep('Fa1e', 7)),
  stripePk: j('pk', '_live_', rep('Pub1', 7)),
  github: j('gh', 'p_', rep('Ab3d', 9)),
  slack: j('xo', 'xb-', '1234567890-', 'FakeTokenValue'),
  openai: j('sk', '-proj-', rep('Op3nAiFake', 5)),
  anthropic: j('sk', '-ant-', 'api03-', rep('AnthFake9', 10)),
  google: j('AI', 'za', 'Sy', rep('G0og', 8), 'F'),          // AIza + 35
  pem: j('-----BEGIN ', 'RSA PRIVATE', ' KEY-----'),
  serviceAccount: j('{"type"', ':', '"service', '_account","project_id":"demo"}'),
  jwtService: j(b64u({ alg: 'HS256', typ: 'JWT' }), '.', b64u({ iss: 'supabase', role: 'service' + '_role' }), '.', rep('s1gNaTuRe', 3)),
  jwtAnon: j(b64u({ alg: 'HS256', typ: 'JWT' }), '.', b64u({ iss: 'supabase', role: 'anon' }), '.', rep('s1gNaTuRe', 3)),
  twilio: j('S', 'K', rep('0123456789abcdef', 2)),
  sendgrid: j('S', 'G.', rep('a', 11), rep('B', 11), '.', rep('c1D2e3F4g5', 4), 'xyz'),
  mailgun: j('ke', 'y-', rep('0a1b2c3d', 4)),
  npm: j('np', 'm_', rep('N9pm', 9)),
  dbUrl: j('postgres', '://', 'admin', ':', 'Hunter2Fake', '@db.example.com:5432/app'),
  generic: j('Zx9', 'Qw8Er7Ty6', 'Ui5Op4As3Df2'),
  envServer: j('srv', '_', 'Kq8Zt2LmVw9Rx4Pn'),
};
