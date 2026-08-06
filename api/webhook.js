import crypto from 'crypto';
import admin from 'firebase-admin';
import { WEBHOOK_EVENTS, ORDER_STATUS, PAYMENT_STATUS } from './constants.js';

// Initialize Firebase Admin if not already initialized
if (!admin.apps.length) {
  // On Vercel, you should add your Firebase Service Account JSON as an environment variable (e.g. FIREBASE_SERVICE_ACCOUNT)
  // For local development, you can use a fallback or require the json directly if it's there.
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
    if (Object.keys(serviceAccount).length > 0) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
    } else {
      console.warn("FIREBASE_SERVICE_ACCOUNT env variable is not set or empty. Firestore updates will fail if not authenticated.");
      // Fallback for local testing if running via `firebase emulators` or similar
      admin.initializeApp(); 
    }
  } catch (e) {
    console.error("Firebase Admin Initialization Error:", e);
  }
}

const db = admin.firestore();

// Razorpay Webhook Secret (Set this in Vercel Environment Variables)
const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || 'your_webhook_secret_here';

export default async function handler(req, res) {
  console.log("🔔 WEBHOOK HIT! Event received!");
  console.log(req.body);

  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature) {
      return res.status(400).json({ error: 'Missing Signature' });
    }

    // Razorpay webhook payload comes as a JSON string in req.body. 
    // Depending on body-parser config, it might be an object. If object, stringify it.
    const bodyString = typeof req.body === 'object' ? JSON.stringify(req.body) : req.body;

    // Cryptographically verify the signature
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(bodyString)
      .digest('hex');

    if (expectedSignature !== signature) {
      return res.status(401).json({ error: 'Invalid Signature' });
    }

    // Signature verified! Parse payload if it was stringified
    const payload = typeof req.body === 'object' ? req.body : JSON.parse(req.body);

    // Because we are not using the Razorpay Orders API, payments will default to 'Authorized' instead of 'Captured'.
    // We should treat 'payment.authorized' as a successful transaction for the user, and manually capture it later in the dashboard.
    if (payload.event === WEBHOOK_EVENTS.PAYMENT_CAPTURED || payload.event === WEBHOOK_EVENTS.PAYMENT_AUTHORIZED) {
      const paymentEntity = payload.payload.payment.entity;
      
      // Get the orderId we passed from Flutter in the 'notes' field
      const orderId = paymentEntity.notes.orderId;
      const paymentId = paymentEntity.id;
      const amountPaid = paymentEntity.amount; // in paise

      if (!orderId) {
        console.error("No orderId found in notes. Cannot reconcile.");
        return res.status(200).json({ status: 'ignored', reason: 'No orderId in notes' });
      }

      console.log(`Verifying payment for Order ID: ${orderId}, Amount: ${amountPaid}`);

      // Update Firestore
      const orderRef = db.collection('Orders').doc(orderId);
      const orderDoc = await orderRef.get();

      if (!orderDoc.exists) {
        console.error(`Order ${orderId} does not exist in Firestore!`);
        return res.status(404).json({ error: 'Order not found' });
      }

      const orderData = orderDoc.data();
      // Razorpay sends amount in paise (e.g. 50000 for ₹500).
      // If your Flutter app saves totalAmount as 500, compare carefully.
      const expectedAmountInPaise = Math.round(orderData.total_amount * 100);

      if (amountPaid !== expectedAmountInPaise) {
        console.error(`Amount mismatch! Paid: ${amountPaid}, Expected: ${expectedAmountInPaise}`);
        // Optionally flag the order as 'fraud_suspected' instead of processing
        await orderRef.update({
          paymentId: paymentId,
          status: ORDER_STATUS.PENDING,
          paymentStatus: PAYMENT_STATUS.FAILED_AMOUNT_MISMATCH
        });
        return res.status(400).json({ error: 'Amount mismatch' });
      }

      // Everything is perfectly verified! Mark order as processing
      await orderRef.update({
        paymentId: paymentId,
        status: ORDER_STATUS.PROCESSING,
        paymentStatus: PAYMENT_STATUS.SUCCESS,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      console.log(`Order ${orderId} successfully marked as processing.`);
      return res.status(200).json({ status: 'success' });
    }

    // Acknowledge other events so Razorpay doesn't retry
    return res.status(200).json({ status: 'ignored', event: payload.event });

  } catch (error) {
    console.error('Webhook Error:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
};
