const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors({ origin: 'http://localhost:5173' }));

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.get('/protected', async (req, res) => {
  const idToken = req.headers.authorization;

  if (!idToken) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
    // Token is valid, proceed with the protected action
    res.status(200).json({ message: 'Protected data' });
} catch (error) {
    console.error('Error verifying token:', error.message);
    res.status(401).send('Unauthorized');
  }
});

app.post('/logout', async (req, res) => {
    const idToken = req.headers.authorization;
  
    if (!idToken) {
      return res.status(401).send('Unauthorized');
    }
  
    try {
      const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
      const uid = decodedToken.uid;
  
      if (!uid) {
        return res.status(401).send('Unauthorized');
      }
  
      await admin.auth().revokeRefreshTokens(uid);
      res.send('Signed out successfully');
    } catch (error) {
      console.error('Error signing out:', error.message);
      res.status(500).send('Failed to sign out');
    }
  });
  

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
