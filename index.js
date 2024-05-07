const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: 'https://chakra-reservation.firebaseio.com'
});

const db = admin.firestore();

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors({ origin: 'http://localhost:5173' }));

app.get('/', (req, res) => {
    res.send('Hello World!');
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

app.post('/createProduct', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken) {
        return res.status(401).send('Unauthorized');
    }

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        if (role !== 'admin') {
            return res.status(403).send('Forbidden');
        }

        // Extract data from the request body
        const data = req.body;

        const docRef = await db.collection('products').add(data);

        res.status(200).json({ message: 'Data stored successfully', docId: docRef.id });
    } catch (error) {
        console.error('Error storing data:', error.message);
        res.status(500).send('Failed to store data');
    }
});

app.get('/getProducts', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken) {
        return res.status(401).send('Unauthorized');
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
        const querySnapshot = await db.collection('products').get();
        const products = querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.status(200).json(products);
    } catch (error) {
        console.error('Error verifying token or fetching products:', error.message);
        res.status(500).send('Failed to fetch products');
    }
});

app.post('/modifyProduct', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken) {
        return res.status(401).send('Unauthorized');
    }

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        if (role !== 'admin') {
            return res.status(403).send('Forbidden');
        }

        const { uid: productUid, name } = req.body;
        if (!productUid || !name) {
            return res.status(400).send('Product UID or name not provided');
        }

        await db.collection('products').doc(productUid).update({ name });

        res.status(200).send('Product modified successfully');
    } catch (error) {
        console.error('Error modifying product:', error.message);
        res.status(500).send('Failed to modify product');
    }
});

app.delete('/deleteProduct', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken) {
        return res.status(401).send('Unauthorized');
    }

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        if (role !== 'admin') {
            return res.status(403).send('Forbidden');
        }

        // Check if the request body contains the UID to delete
        const { uid: productUid } = req.body;
        if (!productUid) {
            return res.status(400).send('Product UID not provided');
        }

        // Check if the product exists
        const productDoc = await db.collection('products').doc(productUid).get();
        if (!productDoc.exists) {
            return res.status(404).send('Product not found');
        }

        // Delete the product from Firestore
        await db.collection('products').doc(productUid).delete();

        res.status(200).send('Product deleted successfully');
    } catch (error) {
        console.error('Error deleting product:', error.message);
        res.status(500).send('Failed to delete product');
    }
});


async function getRoleById(userId) {
    try {
        // Query Firestore to check if the UID exists in the document
        const docRef = db.collection('roles').doc('roleAssignment');
        const doc = await docRef.get();

        // Determine the role based on the document
        if (doc.exists) {
            const data = doc.data();

            if (data.admins.includes(userId)) {
                return 'admin';
            } else if (data.users.includes(userId)) {
                return 'user';
            } else {
                return 'guest';
            }
        } else {
            throw new Error('Role assignment document not found');
        }
    } catch (error) {
        console.error('Error checking role:', error.message);
        throw new Error('Failed to check role');
    }
}

app.post('/check-role', async (req, res) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        // Verify the Firebase token
        const decodedToken = await admin.auth().verifyIdToken(token.split(' ')[1]);
        const userId = decodedToken.uid;

        // Get the role based on the user ID
        const role = await getRoleById(userId);
        res.json({ role });
    } catch (error) {
        console.error('Error checking role:', error.message);
        res.status(500).json({ error: 'Failed to check role' });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
