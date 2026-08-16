// ============================================================================
// Squadly — firebase-config.js
// تهيئة Firebase + دوال المصادقة + Firestore + الأمان (Sanitization / Rate limit)
// ============================================================================

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  updateProfile,
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import {
  getFirestore,
  doc,
  setDoc,
  getDoc,
  updateDoc,
  addDoc,
  collection,
  query,
  where,
  orderBy,
  onSnapshot,
  serverTimestamp,
  runTransaction,
  increment,
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";
import {
  getStorage,
  ref,
  uploadBytes,
  getDownloadURL,
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-storage.js";

// ---- إعدادات مشروع Squadly ----
const firebaseConfig = {
  apiKey: "AIzaSyACL2nG7OdUuU4HRippr7P46OJpPpDYf5g",
  authDomain: "squadly-bb782.firebaseapp.com",
  projectId: "squadly-bb782",
  storageBucket: "squadly-bb782.firebasestorage.app",
  messagingSenderId: "605956538187",
  appId: "1:605956538187:web:bac92b0e4f087be0e232ce",
  measurementId: "G-SGCQ032MP7",
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);

// نسب المنصة الثابتة — يجب أن تُحسب دائمًا من هنا وليست بأرقام حرة في الواجهة
export const PLATFORM_FEE_RATE = 0.25;
export const FREELANCER_RATE = 0.75;

/* ============================================================================
   1) الأمان الأساسي: Sanitization + Rate limiting
   ملاحظة مهمة: هذه حماية على مستوى الـ Frontend فقط لتحسين تجربة المستخدم
   ومنع أخطاء أو محاولات بدائية. الحماية الحقيقية والملزمة هي Firestore/Storage
   Security Rules (انظر firestore.rules و storage.rules) والتحقق من صلاحية
   الأدمن عبر Custom Claims على الخادم — لا تعتمد أبدًا على كود المتصفح وحده.
   ============================================================================ */

// إزالة أي وسوم HTML/سكربت من أي نص يُدخله المستخدم قبل تخزينه أو عرضه (منع XSS)
export function sanitizeInput(value) {
  if (typeof value !== "string") return value;
  return value
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;")
    .replace(/javascript:/gi, "")
    .replace(/on\w+\s*=/gi, "")
    .trim()
    .slice(0, 2000);
}

// تعقيم كائن كامل (كل الحقول النصية داخل الفورم) دفعة واحدة
export function sanitizeObject(obj) {
  const clean = {};
  for (const key in obj) {
    clean[key] = sanitizeInput(obj[key]);
  }
  return clean;
}

// تحقق بسيط من صحة البريد الإلكتروني قبل الإرسال لـ Firebase
export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// تحقق من قوة كلمة المرور (8 أحرف على الأقل، حرف ورقم)
export function isStrongPassword(pw) {
  return typeof pw === "string" && pw.length >= 8 && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}

// Rate Limiter بسيط قائم على sessionStorage لمنع Brute Force على أزرار
// تسجيل الدخول وإرسال طلب التوثيق (تُستكمل حمايته الحقيقية عبر Firebase
// App Check و Cloud Functions rate limiting على الخادم)
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // دقيقة واحدة
const RATE_LIMIT_MAX_ATTEMPTS = 5;

export function checkRateLimit(actionKey) {
  const now = Date.now();
  const storageKey = `squadly_rl_${actionKey}`;
  let record;
  try {
    record = JSON.parse(sessionStorage.getItem(storageKey)) || { count: 0, start: now };
  } catch {
    record = { count: 0, start: now };
  }

  if (now - record.start > RATE_LIMIT_WINDOW_MS) {
    record = { count: 0, start: now };
  }

  record.count += 1;
  sessionStorage.setItem(storageKey, JSON.stringify(record));

  if (record.count > RATE_LIMIT_MAX_ATTEMPTS) {
    const secondsLeft = Math.ceil((RATE_LIMIT_WINDOW_MS - (now - record.start)) / 1000);
    return { allowed: false, secondsLeft: Math.max(secondsLeft, 1) };
  }
  return { allowed: true };
}

/* ============================================================================
   2) المصادقة — تسجيل الدخول / إنشاء حساب
   ============================================================================ */

export async function registerUser({ name, email, password, role }) {
  const rl = checkRateLimit("register");
  if (!rl.allowed) throw new Error(`محاولات كثيرة جدًا، حاول بعد ${rl.secondsLeft} ثانية`);

  const clean = sanitizeObject({ name, email, role });
  if (!isValidEmail(clean.email)) throw new Error("البريد الإلكتروني غير صالح");
  if (!isStrongPassword(password)) throw new Error("كلمة المرور يجب أن تكون 8 أحرف على الأقل وتحتوي على أرقام");
  if (!["client", "freelancer"].includes(clean.role)) throw new Error("نوع الحساب غير صالح");

  const cred = await createUserWithEmailAndPassword(auth, clean.email, password);
  await updateProfile(cred.user, { displayName: clean.name });

  // إنشاء وثيقة المستخدم في users — القراءة/الكتابة محكومة بـ firestore.rules
  await setDoc(doc(db, "users", cred.user.uid), {
    uid: cred.user.uid,
    name: clean.name,
    email: clean.email,
    role: clean.role,
    isVerified: false,
    balance: 0,
    createdAt: serverTimestamp(),
  });

  await createNotification(cred.user.uid, "مرحبًا بك في Squadly", "تم إنشاء حسابك بنجاح، أكمل ملفك الشخصي للبدء.");
  return cred.user;
}

export async function loginUser({ email, password }) {
  const rl = checkRateLimit("login");
  if (!rl.allowed) throw new Error(`محاولات دخول كثيرة، حاول بعد ${rl.secondsLeft} ثانية`);

  const clean = sanitizeObject({ email });
  if (!isValidEmail(clean.email)) throw new Error("البريد الإلكتروني غير صالح");

  const cred = await signInWithEmailAndPassword(auth, clean.email, password);
  return cred.user;
}

export function logoutUser() {
  return signOut(auth);
}

export function watchAuthState(callback) {
  return onAuthStateChanged(auth, callback);
}

// جلب بيانات المستخدم من Firestore (تتضمن role و isVerified)
export async function getUserProfile(uid) {
  const snap = await getDoc(doc(db, "users", uid));
  return snap.exists() ? snap.data() : null;
}

/* ============================================================================
   3) طلبات التوثيق — verification_requests
   ============================================================================ */

export async function submitVerificationRequest({ uid, nationalIdFile, portfolioUrl }) {
  const rl = checkRateLimit("verify_submit");
  if (!rl.allowed) throw new Error(`لا يمكنك إرسال طلبات متكررة، حاول بعد ${rl.secondsLeft} ثانية`);

  if (!nationalIdFile) throw new Error("يرجى إرفاق صورة الهوية");

  // رفع صورة الهوية لمجلد خاص بالمستخدم — القراءة محصورة على الأدمن فقط
  // (انظر storage.rules) لضمان سرية مستندات الهوية
  const idRef = ref(storage, `verification_docs/${uid}/national_id_${Date.now()}`);
  await uploadBytes(idRef, nationalIdFile);
  const nationalIdUrl = await getDownloadURL(idRef);

  const clean = sanitizeObject({ portfolioUrl });

  const docRef = await addDoc(collection(db, "verification_requests"), {
    userId: uid,
    nationalIdUrl,
    portfolioUrl: clean.portfolioUrl || "",
    status: "pending",
    submittedAt: serverTimestamp(),
  });

  await createNotification(uid, "تم استلام طلب التوثيق", "سيقوم فريقنا بمراجعة هويتك خلال 24-48 ساعة.");
  return docRef.id;
}

// (تُستخدم في admin.html) الاستماع الحي لطلبات التوثيق
export function listenVerificationRequests(callback) {
  const q = query(collection(db, "verification_requests"), orderBy("submittedAt", "desc"));
  return onSnapshot(q, (snap) => {
    callback(snap.docs.map((d) => ({ id: d.id, ...d.data() })));
  });
}

// موافقة/رفض طلب توثيق — يجب استدعاؤها فقط من واجهة أدمن محمية بـ requireAdmin()
export async function reviewVerificationRequest(requestId, userId, decision /* 'approved' | 'rejected' */) {
  await updateDoc(doc(db, "verification_requests", requestId), {
    status: decision,
    reviewedAt: serverTimestamp(),
  });

  if (decision === "approved") {
    await updateDoc(doc(db, "users", userId), { isVerified: true });
    await createNotification(userId, "تم توثيق حسابك ✅", "تهانينا! أصبح حسابك موثقًا ويمكنك الآن استقبال المهام والدفعات.");
  } else {
    await createNotification(userId, "تم رفض طلب التوثيق", "يرجى مراجعة المستندات المطلوبة وإعادة التقديم.");
  }
}

/* ============================================================================
   4) منطق الضمان المالي (Escrow Logic) — jobs + transactions
   ============================================================================ */

// (أ) دفع العميل: حجز المبلغ بالكامل داخل حساب Escrow الخاص بالمهمة
export async function createEscrowJob({ clientId, freelancerId, totalAmount, title }) {
  const amount = Number(totalAmount);
  if (!amount || amount <= 0) throw new Error("قيمة المبلغ غير صالحة");

  const platformFee = +(amount * PLATFORM_FEE_RATE).toFixed(2);
  const freelancerAmount = +(amount * FREELANCER_RATE).toFixed(2);

  const jobRef = await addDoc(collection(db, "jobs"), {
    title: sanitizeInput(title || ""),
    clientId,
    freelancerId,
    totalAmount: amount,
    platformFee,
    freelancerAmount,
    status: "escrowed",
    createdAt: serverTimestamp(),
  });

  await addDoc(collection(db, "transactions"), {
    userId: clientId,
    jobId: jobRef.id,
    amount,
    type: "deposit",
    timestamp: serverTimestamp(),
  });

  await createNotification(clientId, "تم حجز المبلغ في الضمان", `تم حجز ${amount} ج.م بنجاح حتى اكتمال المهمة.`);
  await createNotification(freelancerId, "مهمة جديدة بانتظارك", "تم حجز مستحقاتك في نظام الضمان، ابدأ العمل الآن.");

  return jobRef.id;
}

// (ب) إكمال المهمة: توزيع تلقائي — خصم 25% للمنصة وتحويل 75% لرصيد المستقل
// تُنفَّذ داخل Transaction لضمان عدم ازدواج الصرف (atomic)
export async function completeJobAndPayout(jobId) {
  return runTransaction(db, async (transaction) => {
    const jobRef = doc(db, "jobs", jobId);
    const jobSnap = await transaction.get(jobRef);
    if (!jobSnap.exists()) throw new Error("المهمة غير موجودة");

    const job = jobSnap.data();
    if (job.status !== "escrowed") throw new Error("لا يمكن تحويل مبلغ مهمة غير محجوزة في الضمان");

    const freelancerRef = doc(db, "users", job.freelancerId);
    const freelancerSnap = await transaction.get(freelancerRef);
    if (!freelancerSnap.exists() || !freelancerSnap.data().isVerified) {
      throw new Error("لا يمكن تحويل المستحقات إلا لمستقل موثق (Verified)");
    }

    // تحديث رصيد المستقل بـ 75% من المبلغ
    transaction.update(freelancerRef, { balance: increment(job.freelancerAmount) });
    // إغلاق المهمة
    transaction.update(jobRef, { status: "completed", completedAt: serverTimestamp() });

    // تسجيل معاملتي: عمولة المنصة + تحويل المستقل
    const payoutRef = doc(collection(db, "transactions"));
    transaction.set(payoutRef, {
      userId: job.freelancerId,
      jobId,
      amount: job.freelancerAmount,
      type: "payout",
      timestamp: serverTimestamp(),
    });

    const commissionRef = doc(collection(db, "transactions"));
    transaction.set(commissionRef, {
      userId: "platform",
      jobId,
      amount: job.platformFee,
      type: "commission",
      timestamp: serverTimestamp(),
    });

    return { freelancerAmount: job.freelancerAmount, platformFee: job.platformFee };
  }).then(async (result) => {
    const jobSnap = await getDoc(doc(db, "jobs", jobId));
    const job = jobSnap.data();
    await createNotification(job.clientId, "تم تسليم المهمة", "تم تأكيد اكتمال المهمة وتحويل المستحقات للمستقل.");
    await createNotification(job.freelancerId, "تم تحويل مستحقاتك 💰", `تم إيداع ${result.freelancerAmount} ج.م في رصيدك.`);
    return result;
  });
}

/* ============================================================================
   5) نظام التنبيهات — notifications
   ============================================================================ */

export async function createNotification(userId, title, body) {
  await addDoc(collection(db, "notifications"), {
    userId,
    title: sanitizeInput(title),
    body: sanitizeInput(body),
    read: false,
    createdAt: serverTimestamp(),
  });
}

export function listenUserNotifications(uid, callback) {
  const q = query(collection(db, "notifications"), where("userId", "==", uid), orderBy("createdAt", "desc"));
  return onSnapshot(q, (snap) => callback(snap.docs.map((d) => ({ id: d.id, ...d.data() }))));
}

/* ============================================================================
   6) صلاحيات الأدمن — يجب التحقق من الـ Custom Claim "admin" الصادر من
   الخادم (Cloud Function) وليس من حقل Firestore وحده، لأن أي مستند يمكن
   قراءته من المتصفح. هذا التحقق هنا هو طبقة تجربة مستخدم إضافية فقط.
   ============================================================================ */

export async function requireAdmin(user) {
  if (!user) throw new Error("يجب تسجيل الدخول أولاً");
  const tokenResult = await user.getIdTokenResult(true);
  if (!tokenResult.claims.admin) {
    throw new Error("غير مصرح لك بالوصول لهذه الصفحة");
  }
  return true;
}

/* ============================================================================
   7) بوابة دخول الأدمن السرية (المودال المخفي في index.html)
   لا يوجد أي إيميل أو باسورد أو PIN مكتوب هنا بشكل ثابت — كل التحقق يتم عبر
   Firebase Authentication الحقيقي، ثم عبر Admin Custom Claim الصادر من
   Cloud Function (grantAdminRole) على الخادم. هذا هو الفرق الجوهري بين
   "حماية حقيقية" و"إخفاء بصري فقط": أي نص يوضع داخل ملف JS يصل لكل من يفتح
   Developer Tools، بينما الـ Custom Claims لا يمكن تزويرها من المتصفح.
   ============================================================================ */
export async function adminLogin({ email, password }) {
  const rl = checkRateLimit("admin_login");
  if (!rl.allowed) throw new Error(`محاولات كثيرة جدًا، حاول بعد ${rl.secondsLeft} ثانية`);

  const clean = sanitizeObject({ email });
  if (!isValidEmail(clean.email)) throw new Error("البريد الإلكتروني غير صالح");

  const cred = await signInWithEmailAndPassword(auth, clean.email, password);

  try {
    await requireAdmin(cred.user);
  } catch (err) {
    // تسجيل خروج فوري لأي مستخدم غير أدمن حتى لا تبقى جلسة مفتوحة بالخطأ
    await signOut(auth);
    throw new Error("هذا الحساب لا يملك صلاحية الوصول للوحة التحكم");
  }

  return cred.user;
}
