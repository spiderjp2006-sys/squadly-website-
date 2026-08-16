// ============================================================================
// Squadly — Cloud Functions
// المنطق المالي الحساس (اعتماد التوثيق، توزيع 25%/75%) يُنفَّذ هنا على الخادم
// فقط، وليس من المتصفح، لأن هذا هو المكان الوحيد الموثوق للتحقق من صلاحية
// الأدمن ولإجراء التحويلات المالية بأمان (atomic + auditable).
// ============================================================================

const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

const db = admin.firestore();

const PLATFORM_FEE_RATE = 0.25;
const FREELANCER_RATE = 0.75;

// ---- تحقق موحّد من أن المستدعي أدمن حقيقي (Custom Claim) قبل أي عملية حساسة ----
function assertAdmin(context) {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "يجب تسجيل الدخول أولاً");
  }
  if (context.auth.token.admin !== true) {
    throw new functions.https.HttpsError("permission-denied", "هذا الإجراء متاح للأدمن فقط");
  }
}

/* ============================================================================
   1) منح صلاحية أدمن لمستخدم — تُستدعى مرة واحدة يدويًا من قبل أدمن رئيسي
   موجود بالفعل (bootstrap)، أو من سكربت إداري خارج الواجهة العامة.
   ============================================================================ */
exports.grantAdminRole = functions.https.onCall(async (data, context) => {
  assertAdmin(context);
  const { targetUid } = data;
  if (!targetUid) throw new functions.https.HttpsError("invalid-argument", "targetUid مطلوب");

  await admin.auth().setCustomUserClaims(targetUid, { admin: true });
  await db.collection("users").doc(targetUid).update({ role: "admin" });
  return { success: true };
});

/* ============================================================================
   2) مراجعة طلب توثيق (موافقة/رفض) — Admin only
   ============================================================================ */
exports.reviewVerification = functions.https.onCall(async (data, context) => {
  assertAdmin(context);
  const { requestId, decision } = data; // decision: 'approved' | 'rejected'
  if (!["approved", "rejected"].includes(decision)) {
    throw new functions.https.HttpsError("invalid-argument", "قرار غير صالح");
  }

  const reqRef = db.collection("verification_requests").doc(requestId);
  const reqSnap = await reqRef.get();
  if (!reqSnap.exists) throw new functions.https.HttpsError("not-found", "الطلب غير موجود");

  const request = reqSnap.data();

  await reqRef.update({
    status: decision,
    reviewedAt: admin.firestore.FieldValue.serverTimestamp(),
    reviewedBy: context.auth.uid,
  });

  if (decision === "approved") {
    await db.collection("users").doc(request.userId).update({ isVerified: true });
  }

  await db.collection("notifications").add({
    userId: request.userId,
    title: decision === "approved" ? "تم توثيق حسابك ✅" : "تم رفض طلب التوثيق",
    body:
      decision === "approved"
        ? "تهانينا! أصبح حسابك موثقًا ويمكنك الآن استقبال المهام والدفعات."
        : "يرجى مراجعة المستندات المطلوبة وإعادة التقديم.",
    read: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return { success: true, status: decision };
});

/* ============================================================================
   3) دفع العميل: حجز المبلغ في Escrow — يمكن استدعاؤها من العميل نفسه
   ============================================================================ */
exports.createEscrowJob = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "يجب تسجيل الدخول");

  const { freelancerId, totalAmount, title } = data;
  const amount = Number(totalAmount);
  if (!amount || amount <= 0) throw new functions.https.HttpsError("invalid-argument", "قيمة غير صالحة");

  const freelancerSnap = await db.collection("users").doc(freelancerId).get();
  if (!freelancerSnap.exists) throw new functions.https.HttpsError("not-found", "المستقل غير موجود");

  const platformFee = +(amount * PLATFORM_FEE_RATE).toFixed(2);
  const freelancerAmount = +(amount * FREELANCER_RATE).toFixed(2);

  const jobRef = await db.collection("jobs").add({
    title: String(title || "").slice(0, 200),
    clientId: context.auth.uid,
    freelancerId,
    totalAmount: amount,
    platformFee,
    freelancerAmount,
    status: "escrowed",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  await db.collection("transactions").add({
    userId: context.auth.uid,
    jobId: jobRef.id,
    amount,
    type: "deposit",
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });

  await db.collection("notifications").add({
    userId: freelancerId,
    title: "مهمة جديدة بانتظارك",
    body: "تم حجز مستحقاتك في نظام الضمان، ابدأ العمل الآن.",
    read: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return { jobId: jobRef.id, platformFee, freelancerAmount };
});

/* ============================================================================
   4) إكمال المهمة والتوزيع التلقائي (25% منصة / 75% مستقل) — Admin only
   تُنفَّذ داخل Firestore Transaction لضمان عدم تكرار الصرف.
   ============================================================================ */
exports.completeJobAndPayout = functions.https.onCall(async (data, context) => {
  assertAdmin(context);
  const { jobId } = data;

  const result = await db.runTransaction(async (t) => {
    const jobRef = db.collection("jobs").doc(jobId);
    const jobSnap = await t.get(jobRef);
    if (!jobSnap.exists) throw new functions.https.HttpsError("not-found", "المهمة غير موجودة");

    const job = jobSnap.data();
    if (job.status !== "escrowed") {
      throw new functions.https.HttpsError("failed-precondition", "المهمة ليست في حالة ضمان قابلة للتحويل");
    }

    const freelancerRef = db.collection("users").doc(job.freelancerId);
    const freelancerSnap = await t.get(freelancerRef);
    if (!freelancerSnap.exists || !freelancerSnap.data().isVerified) {
      throw new functions.https.HttpsError("failed-precondition", "لا يمكن التحويل إلا لمستقل موثق");
    }

    t.update(freelancerRef, {
      balance: admin.firestore.FieldValue.increment(job.freelancerAmount),
    });
    t.update(jobRef, { status: "completed", completedAt: admin.firestore.FieldValue.serverTimestamp() });

    const payoutRef = db.collection("transactions").doc();
    t.set(payoutRef, {
      userId: job.freelancerId,
      jobId,
      amount: job.freelancerAmount,
      type: "payout",
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    const commissionRef = db.collection("transactions").doc();
    t.set(commissionRef, {
      userId: "platform",
      jobId,
      amount: job.platformFee,
      type: "commission",
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { clientId: job.clientId, freelancerId: job.freelancerId, freelancerAmount: job.freelancerAmount };
  });

  await db.collection("notifications").add({
    userId: result.clientId,
    title: "تم تسليم المهمة",
    body: "تم تأكيد اكتمال المهمة وتحويل المستحقات للمستقل.",
    read: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  await db.collection("notifications").add({
    userId: result.freelancerId,
    title: "تم تحويل مستحقاتك 💰",
    body: `تم إيداع ${result.freelancerAmount} ج.م في رصيدك.`,
    read: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return { success: true };
});

/* ============================================================================
   5) Rate limiting على مستوى الخادم لطلبات التوثيق (حماية إضافية خلف
   الحماية الأمامية الموجودة في firebase-config.js)
   ============================================================================ */
exports.submitVerificationRequest = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "يجب تسجيل الدخول");

  const uid = context.auth.uid;
  const recentSnap = await db
    .collection("verification_requests")
    .where("userId", "==", uid)
    .orderBy("submittedAt", "desc")
    .limit(1)
    .get();

  if (!recentSnap.empty) {
    const last = recentSnap.docs[0].data();
    const lastTime = last.submittedAt ? last.submittedAt.toMillis() : 0;
    if (Date.now() - lastTime < 5 * 60 * 1000) {
      throw new functions.https.HttpsError("resource-exhausted", "يرجى الانتظار قبل إرسال طلب جديد");
    }
  }

  const { nationalIdUrl, portfolioUrl } = data;
  const reqRef = await db.collection("verification_requests").add({
    userId: uid,
    nationalIdUrl: String(nationalIdUrl || "").slice(0, 500),
    portfolioUrl: String(portfolioUrl || "").slice(0, 500),
    status: "pending",
    submittedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return { requestId: reqRef.id };
});
