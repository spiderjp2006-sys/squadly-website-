// ============================================================================
// Squadly — set-admin.js
// سكربت لمرة واحدة فقط: ينشئ حساب الأدمن الأول (matrix2006@gmail.com) ويمنحه
// صلاحية admin مباشرة عبر Firebase Admin SDK. هذا يحل مشكلة "الدجاجة والبيضة":
// دالة grantAdminRole في functions/index.js تتطلب أدمن موجود بالفعل لاستدعائها،
// فهذا السكربت هو الطريقة الوحيدة لإنشاء أول أدمن على الإطلاق.
//
// شغّله مرة واحدة من جهازك، ثم لا تحتاجه مرة أخرى إلا لو أردت إضافة أدمن آخر.
// ============================================================================

const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const ADMIN_EMAIL = "matrix2006@gmail.com";
const ADMIN_PASSWORD = "01224815487"; // غيّرها هنا لو حبيت باسورد مختلف قبل التشغيل

async function main() {
  let user;

  try {
    user = await admin.auth().getUserByEmail(ADMIN_EMAIL);
    console.log("✅ الحساب موجود بالفعل، جاري تحديث كلمة المرور...");
    user = await admin.auth().updateUser(user.uid, { password: ADMIN_PASSWORD });
  } catch (err) {
    if (err.code === "auth/user-not-found") {
      console.log("➕ الحساب غير موجود، جاري إنشاؤه...");
      user = await admin.auth().createUser({
        email: ADMIN_EMAIL,
        password: ADMIN_PASSWORD,
        displayName: "Squadly Admin",
      });
    } else {
      throw err;
    }
  }

  // منح صلاحية admin عبر Custom Claim — هذا هو الفحص الحقيقي المستخدم في
  // firebase-config.js (requireAdmin) و admin.html و firestore.rules
  await admin.auth().setCustomUserClaims(user.uid, { admin: true });

  // مزامنة وثيقة المستخدم في Firestore حتى تظهر بياناته بشكل صحيح في لوحة التحكم
  await admin.firestore().collection("users").doc(user.uid).set(
    {
      uid: user.uid,
      name: "Squadly Admin",
      email: ADMIN_EMAIL,
      role: "admin",
      isVerified: true,
      balance: 0,
    },
    { merge: true }
  );

  console.log("🎉 تم! الحساب أصبح أدمن رسميًا:");
  console.log("   الإيميل:", ADMIN_EMAIL);
  console.log("   UID:", user.uid);
  console.log("");
  console.log("افتح index.html الآن → اضغط على رقم الإصدار في الفوتر 5 مرات متتالية → سجّل دخول بهذا الإيميل والباسورد.");
  process.exit(0);
}

main().catch((err) => {
  console.error("❌ حدث خطأ:", err.message);
  process.exit(1);
});
