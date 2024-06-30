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

async function getNestedCollections(ref, result = []) {
    const collections = await ref.listCollections();
    for (const coll of collections) {
        const docs = await coll.get();
        const data = docs.docs.map(doc => doc.data());
        result.push({ [coll.id]: data });
        for (const doc of docs.docs) {
            await getNestedCollections(doc.ref, result);
        }
    }
    return result;
}

app.get('/getWarehouses', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken) {
        return res.status(401).send('Unauthorized');
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
        const querySnapshot = await db.collection('warehouses').get();
        const warehouses = [];
        for (const doc of querySnapshot.docs) {
            const data = doc.data();
            const nestedCollections = await getNestedCollections(doc.ref);
            data.nestedCollections = nestedCollections;
            data.id = doc.id; // Add the warehouse document ID
            warehouses.push(data);
        }
        res.status(200).json(warehouses);
    } catch (error) {
        console.error('Error verifying token or fetching warehouses:', error.message);
        res.status(500).send('Failed to fetch warehouses');
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

        // Update the product to set disabled to false
        await db.collection('products').doc(productUid).update({ disabled: true });

        res.status(200).send('Product disabled successfully');
    } catch (error) {
        console.error('Error disabling product:', error.message);
        res.status(500).send('Failed to disable product');
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

app.post('/createWarehouse', async (req, res) => {
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
      const { name } = req.body;
  
      // Create a new document in the 'warehouses' collection with the provided name
      const warehouseRef = await db.collection('warehouses').add({ name, disabled: false });

      // Create a new collection 'inventory' nested under the new warehouse document
      const inventoryRef = await warehouseRef.collection('inventory').add({});

      res.status(200).json({ message: 'Warehouse created successfully', warehouseId: warehouseRef.id });
    } catch (error) {
      console.error('Error creating warehouse:', error.message);
      res.status(500).send('Failed to create warehouse');
    }
});

app.post('/modifyWarehouse', async (req, res) => {
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

        // Extract the warehouse ID and new name from the request body
        const { warehouseId, name } = req.body;

        if (!warehouseId || !name) {
            return res.status(400).send('Bad Request: warehouseId and name are required');
        }

        // Update the name field of the warehouse document
        await db.collection('warehouses').doc(warehouseId).update({ name });

        res.status(200).json({ message: 'Warehouse name updated successfully' });
    } catch (error) {
        console.error('Error updating warehouse name:', error.message);
        res.status(500).send('Failed to update warehouse name');
    }
});

app.post('/deleteWarehouse', async (req, res) => {
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

        // Extract the warehouse ID from the request body
        const { warehouseId } = req.body;

        // Update the 'disabled' field of the warehouse document
        await db.collection('warehouses').doc(warehouseId).update({ disabled: true });

        res.status(200).json({ message: 'Warehouse disabled successfully' });
    } catch (error) {
        console.error('Error disabling warehouse:', error.message);
        res.status(500).send('Failed to disable warehouse');
    }
});

app.post('/createCustomer', async (req, res) => {
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

        // Extract company name from the request body
        const { name, disabled } = req.body;

        if (!name) {
            return res.status(400).send('Bad Request: Name is required');
        }

        const customerData = {
            name,
            disabled,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('customers').add(customerData);

        res.status(200).json({ message: 'Customer created successfully', docId: docRef.id });
    } catch (error) {
        console.error('Error creating customer:', error.message);
        res.status(500).send('Failed to create customer');
    }
});

app.get('/getCustomers', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken) {
        return res.status(401).send('Unauthorized');
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken.split(' ')[1]);
        const querySnapshot = await db.collection('customers').get();
        const products = querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.status(200).json(products);
    } catch (error) {
        console.error('Error verifying token or fetching products:', error.message);
        res.status(500).send('Failed to fetch products');
    }
});

app.post('/modifyCustomer', async (req, res) => {
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

        const { uid: customerUid, name } = req.body;
        if (!customerUid || !name) {
            return res.status(400).send('Customer UID or name not provided');
        }

        await db.collection('customers').doc(customerUid).update({ name });

        res.status(200).send('Customer modified successfully');
    } catch (error) {
        console.error('Error modifying customer:', error.message);
        res.status(500).send('Failed to modify customer');
    }
});

app.delete('/deleteCustomer', async (req, res) => {
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
        const { uid: customerUid } = req.body;
        if (!customerUid) {
            return res.status(400).send('Customer UID not provided');
        }

        // Check if the product exists
        const productDoc = await db.collection('customers').doc(customerUid).get();
        if (!productDoc.exists) {
            return res.status(404).send('Product not found');
        }

        // Update the product to set disabled to false
        await db.collection('customers').doc(customerUid).update({ disabled: true });

        res.status(200).send('Customer disabled successfully');
    } catch (error) {
        console.error('Error disabling customer:', error.message);
        res.status(500).send('Failed to disable customer');
    }
});

async function getProductName(productId) {
    try {
        const productDoc = await db.collection('products')
                                 .doc(productId)
                                 .get();

        if (!productDoc.exists) {
            return null; // Product not found
        } else {
            // Return the product name
            return productDoc.data().name;
        }
    } catch (error) {
        console.error('Error fetching product:', error.message);
        throw error;
    }
}


app.post('/modifyProductQuantity', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken || !idToken.startsWith('Bearer ')) {
        console.error('Unauthorized: Missing or invalid token');
        return res.status(401).send('Unauthorized');
    }

    const token = idToken.split(' ')[1];

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(token);
        console.log('Token verified:', decodedToken);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        console.log('User role:', role);
        if (role !== 'admin') {
            console.error('Forbidden: User is not an admin');
            return res.status(403).send('Forbidden');
        }

        // Extract the warehouse ID and updates from the request body
        const { warehouseId, updates } = req.body;
        console.log('Request body:', req.body);

        if (!warehouseId || !Array.isArray(updates) || updates.length === 0) {
            console.error('Bad Request: Invalid warehouseId or updates');
            return res.status(400).send('Bad Request: warehouseId and updates are required');
        }

        const batch = db.batch();

        for (const { productId, quantity } of updates) {
            console.log('Updating product:', productId, 'with quantity:', quantity);
            const productRef = db.collection('warehouses')
                                .doc(warehouseId)
                                .collection('inventory')
                                .where('productId', '==', productId);

            const productSnapshot = await productRef.get();
            if (productSnapshot.empty) {
                // Product not found, add it to the inventory
                const name = await getProductName(productId);
                const newProductRef = db.collection('warehouses')
                                      .doc(warehouseId)
                                      .collection('inventory')
                                      .doc(); // Auto-generated ID

                batch.set(newProductRef, { productId, quantity, name });
                console.log('Added new product:', productId, 'with quantity:', quantity, 'with name:', name);
            } else {
                // Product found, update its quantity
                productSnapshot.forEach((doc) => {
                    const currentQuantity = parseInt(doc.data().quantity, 10);
                    const newQuantity = currentQuantity + parseInt(quantity, 10);
                    console.log('Updating existing product:', doc.id, 'with new quantity:', newQuantity);
                    batch.update(doc.ref, { quantity: newQuantity });
                });
            }
        }

        await batch.commit();
        console.log('Batch commit successful');
        res.status(200).json({ message: 'Product quantities updated successfully' });
    } catch (error) {
        console.error('Error updating product quantities:', error.message);
        res.status(500).send('Failed to update product quantities');
    }
});

// Add this function at the top of your file or in a separate utility file
async function getCompanyName(companyUid) {
    try {
        const companyDoc = await admin.firestore().collection('customers')
                                 .doc(companyUid)
                                 .get();

        if (!companyDoc.exists) {
            return null; // Company not found
        } else {
            // Return the company name
            return companyDoc.data().name;
        }
    } catch (error) {
        console.error('Error fetching company:', error.message);
        throw error;
    }
}

app.post('/createInboundInvoice', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken || !idToken.startsWith('Bearer ')) {
        console.error('Unauthorized: Missing or invalid token');
        return res.status(401).send('Unauthorized');
    }

    const token = idToken.split(' ')[1];

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(token);
        console.log('Token verified:', decodedToken);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        console.log('User role:', role);
        if (role !== 'admin') {
            console.error('Forbidden: User is not an admin');
            return res.status(403).send('Forbidden');
        }

        // Extract the invoice details from the request body
        const { companyUid, products, warehouseId } = req.body;
        console.log('Request body:', req.body);

        if (!companyUid || !Array.isArray(products) || products.length === 0 || !warehouseId) {
            console.error('Bad Request: Invalid companyUid, products, or warehouseId');
            return res.status(400).send('Bad Request: companyUid, products, and warehouseId are required');
        }

        // Validate products array
        for (const product of products) {
            if (!product.productId || typeof product.quantity !== 'number') {
                console.error('Bad Request: Invalid product structure');
                return res.status(400).send('Bad Request: Each product must have a productId and quantity');
            }
        }

        // Get company name
        const companyName = await getCompanyName(companyUid);
        if (!companyName) {
            console.error('Bad Request: Company not found');
            return res.status(400).send('Bad Request: Company not found');
        }

        // Create a new invoice document
        const invoiceRef = admin.firestore().collection('inbound_invoices').doc();

        const invoiceData = {
            company: {
                uid: companyUid,
                name: companyName
            },
            products: products,  // Array of objects with productId and quantity
            warehouseId: warehouseId,
            createdOn: admin.firestore.FieldValue.serverTimestamp(),
            createdBy: uid,  // Adding the ID of the admin who created the invoice
            disabled: false
        };

        await invoiceRef.set(invoiceData);
        console.log('Invoice created successfully:', invoiceRef.id);

        res.status(200).json({ 
            message: 'Invoice created successfully', 
            invoiceId: invoiceRef.id 
        });
    } catch (error) {
        console.error('Error creating invoice:', error.message);
        res.status(500).send('Failed to create invoice');
    }
});

app.get('/getInvoices', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken || !idToken.startsWith('Bearer ')) {
        console.error('Unauthorized: Missing or invalid token');
        return res.status(401).send('Unauthorized');
    }

    const token = idToken.split(' ')[1];

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(token);
        console.log('Token verified:', decodedToken);
        const uid = decodedToken.uid;

        // Check if the user is an admin (optional, remove if not needed)
        const role = await getRoleById(uid);
        console.log('User role:', role);
        if (role !== 'admin') {
            console.error('Forbidden: User is not an admin');
            return res.status(403).send('Forbidden');
        }

        // Fetch all invoices
        const querySnapshot = await admin.firestore().collection('inbound_invoices').get();
        const invoices = querySnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            createdOn: doc.data().createdOn ? doc.data().createdOn.toDate() : null
        }));

        console.log(`Fetched ${invoices.length} invoices`);
        res.status(200).json(invoices);
    } catch (error) {
        console.error('Error verifying token or fetching invoices:', error.message);
        res.status(500).send('Failed to fetch invoices');
    }
});

app.post('/deleteInboundInvoice', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken || !idToken.startsWith('Bearer ')) {
        console.error('Unauthorized: Missing or invalid token');
        return res.status(401).send('Unauthorized');
    }

    const token = idToken.split(' ')[1];

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(token);
        console.log('Token verified:', decodedToken);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        console.log('User role:', role);
        if (role !== 'admin') {
            console.error('Forbidden: User is not an admin');
            return res.status(403).send('Forbidden');
        }

        // Extract the invoice ID from the request body
        const { invoiceId } = req.body;
        console.log('Request body:', req.body);

        if (!invoiceId) {
            console.error('Bad Request: Missing invoiceId');
            return res.status(400).send('Bad Request: invoiceId is required');
        }

        // Get a reference to the invoice document
        const invoiceRef = admin.firestore().collection('inbound_invoices').doc(invoiceId);

        // Check if the invoice exists
        const doc = await invoiceRef.get();
        if (!doc.exists) {
            console.error('Not Found: Invoice does not exist');
            return res.status(404).send('Not Found: Invoice does not exist');
        }

        // Update the disabled field to true
        await invoiceRef.update({
            disabled: true,
            disabledOn: admin.firestore.FieldValue.serverTimestamp(),
            disabledBy: uid
        });

        console.log('Invoice soft deleted successfully:', invoiceId);

        res.status(200).json({ 
            message: 'Invoice soft deleted successfully', 
            invoiceId: invoiceId 
        });
    } catch (error) {
        console.error('Error soft deleting invoice:', error.message);
        res.status(500).send('Failed to soft delete invoice');
    }
});

app.post('/createOutboundInvoice', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken || !idToken.startsWith('Bearer ')) {
        console.error('Unauthorized: Missing or invalid token');
        return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    }

    const token = idToken.split(' ')[1];

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(token);
        console.log('Token verified:', decodedToken);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        console.log('User role:', role);
        if (role !== 'admin') {
            console.error('Forbidden: User is not an admin');
            return res.status(403).json({ error: 'Forbidden: User is not an admin' });
        }

        // Extract the invoice details from the request body
        const { companyUid, products, warehouseId } = req.body;
        console.log('Request body:', req.body);

        if (!companyUid || !Array.isArray(products) || products.length === 0 || !warehouseId) {
            console.error('Bad Request: Invalid companyUid, products, or warehouseId');
            return res.status(400).json({ error: 'Bad Request: companyUid, products, and warehouseId are required' });
        }

        // Validate products array
        for (const product of products) {
            if (!product.productId || typeof product.quantity !== 'number') {
                console.error('Bad Request: Invalid product structure');
                return res.status(400).json({ error: 'Bad Request: Each product must have a productId and quantity' });
            }
        }

        // Get company name
        const companyName = await getCompanyName(companyUid);
        if (!companyName) {
            console.error('Bad Request: Company not found');
            return res.status(400).json({ error: 'Bad Request: Company not found' });
        }

        // Create a new outbound invoice document
        const invoiceRef = admin.firestore().collection('outbound_invoices').doc();

        const invoiceData = {
            company: {
                uid: companyUid,
                name: companyName
            },
            products: products,  // Array of objects with productId and quantity
            warehouseId: warehouseId,
            createdOn: admin.firestore.FieldValue.serverTimestamp(),
            createdBy: uid,  // Adding the ID of the admin who created the invoice
            disabled: false
        };

        await invoiceRef.set(invoiceData);
        console.log('Outbound invoice created successfully:', invoiceRef.id);

        res.status(200).json({ 
            message: 'Outbound invoice created successfully', 
            invoiceId: invoiceRef.id 
        });
    } catch (error) {
        console.error('Error creating outbound invoice:', error.message);
        res.status(500).json({ error: `Failed to create outbound invoice: ${error.message}` });
    }
});

app.get('/getOutboundInvoices', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken || !idToken.startsWith('Bearer ')) {
        console.error('Unauthorized: Missing or invalid token');
        return res.status(401).send('Unauthorized');
    }

    const token = idToken.split(' ')[1];

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(token);
        console.log('Token verified:', decodedToken);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        console.log('User role:', role);
        if (role !== 'admin') {
            console.error('Forbidden: User is not an admin');
            return res.status(403).send('Forbidden');
        }

        // Fetch outbound invoices
        const querySnapshot = await admin.firestore().collection('outbound_invoices').get();
        const outboundInvoices = querySnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            createdOn: doc.data().createdOn ? doc.data().createdOn.toDate() : null
        }));

        console.log(`Fetched ${outboundInvoices.length} outbound invoices`);
        res.status(200).json(outboundInvoices);
    } catch (error) {
        console.error('Error fetching outbound invoices:', error.message);
        res.status(500).send('Failed to fetch outbound invoices');
    }
});

app.post('/deleteOutboundInvoice', async (req, res) => {
    const idToken = req.headers.authorization;

    if (!idToken || !idToken.startsWith('Bearer ')) {
        console.error('Unauthorized: Missing or invalid token');
        return res.status(401).send('Unauthorized');
    }

    const token = idToken.split(' ')[1];

    try {
        // Verify the ID token
        const decodedToken = await admin.auth().verifyIdToken(token);
        console.log('Token verified:', decodedToken);
        const uid = decodedToken.uid;

        // Check if the user is an admin
        const role = await getRoleById(uid);
        console.log('User role:', role);
        if (role !== 'admin') {
            console.error('Forbidden: User is not an admin');
            return res.status(403).send('Forbidden');
        }

        // Extract the invoice ID from the request body
        const { invoiceId } = req.body;
        console.log('Request body:', req.body);

        if (!invoiceId) {
            console.error('Bad Request: Missing invoiceId');
            return res.status(400).send('Bad Request: invoiceId is required');
        }

        // Get a reference to the invoice document
        const invoiceRef = admin.firestore().collection('outbound_invoices').doc(invoiceId);

        // Check if the invoice exists
        const doc = await invoiceRef.get();
        if (!doc.exists) {
            console.error('Not Found: Outbound invoice does not exist');
            return res.status(404).send('Not Found: Outbound invoice does not exist');
        }

        // Update the disabled field to true
        await invoiceRef.update({
            disabled: true,
            disabledOn: admin.firestore.FieldValue.serverTimestamp(),
            disabledBy: uid
        });

        console.log('Outbound invoice soft deleted successfully:', invoiceId);

        res.status(200).json({ 
            message: 'Outbound invoice soft deleted successfully', 
            invoiceId: invoiceId 
        });
    } catch (error) {
        console.error('Error soft deleting outbound invoice:', error.message);
        res.status(500).send('Failed to soft delete outbound invoice');
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
