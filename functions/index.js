const { initializeApp } = require('firebase-admin/app');
const { FieldValue, getFirestore } = require('firebase-admin/firestore');
const { defineString } = require('firebase-functions/params');
const { onDocumentWritten } = require('firebase-functions/v2/firestore');

initializeApp();
const db = getFirestore();
const region = defineString('WORKROOM_FUNCTION_REGION', {
  description: 'Cloud Functions region compatible with the project Firestore location',
});
const beautyTheme = 'theme_beauty_eye';
const stateRef = db.doc('config/estado');
const publicRef = db.doc('config/entregas_publicas');

function isEligible(profile) {
  return profile?.role === 'estilista' && !profile.disabled && !profile.out &&
    !profile.eliminado && profile.ativo !== false && String(profile.status || '').toUpperCase() !== 'OUT';
}

function beautyReleased(data) {
  return ['assigned', 'exhibition'].includes(data?.phase);
}

function updateCounter({ rounds, beautyRound } = {}) {
  return db.runTransaction(async transaction => {
    const state = (await transaction.get(stateRef)).data() || {};
    const round = state.rodada;
    if (!round || (rounds && !rounds.some(value => String(value) === String(round)))) return;
    const beauty = state.themeId === beautyTheme;
    if (beautyRound && (!beauty || beautyRound !== String(round))) return;
    const roundKey = String(round);
    const looksQuery = db.collection('looks');
    const roundLooks = /^\d+$/.test(roundKey) && String(Number(roundKey)) === roundKey
      ? looksQuery.where('rodada', 'in', [roundKey, Number(roundKey)])
      : looksQuery.where('rodada', '==', round);
    const [current, profiles, looks, beautySnapshot] = await Promise.all([
      transaction.get(publicRef),
      transaction.get(db.collection('perfis').where('role', '==', 'estilista')
        .select('role', 'disabled', 'out', 'eliminado', 'ativo', 'status')),
      transaction.get(roundLooks.select('uid', 'slot')),
      beauty ? transaction.get(db.doc(`beauty_dinamicas/${round}`)) : null,
    ]);
    const released = beautyReleased(beautySnapshot?.data());
    const required = beauty ? (released ? 2 : 1) : state.fase === 'final' ? 4 : Number(state.numSubmissoes) || 1;
    const counts = new Map(profiles.docs.filter(doc => isEligible(doc.data())).map(doc => [doc.id, 0]));
    for (const doc of looks.docs) {
      const { uid, slot } = doc.data();
      if (counts.has(uid) && (!beauty || released || Number(slot || 1) === 1)) {
        counts.set(uid, counts.get(uid) + 1);
      }
    }
    // Preserve the public Week 02 cap already applied by the site.
    const total = Number(round) === 2 || state.themeId === 'w02_new_form' ? Math.min(18, counts.size) : counts.size;
    const enviados = Math.min(total, [...counts.values()].filter(count => count >= required).length);
    const rodada = roundKey;
    const published = current.data() || {};
    if (published.rodada === rodada && published.enviados === enviados && published.total === total) return;

    transaction.set(publicRef, { rodada, enviados, total, updatedAt: FieldValue.serverTimestamp() });
  });
}

function watch(document, handler) {
  return onDocumentWritten({ document, region, retry: true }, event => {
    if (event.data) return handler(event.data.before.data(), event.data.after.data(), event.params);
  });
}

exports.workroomCountOnLook = watch('looks/{id}', (before, after) => {
  const fields = ['rodada', 'uid', 'slot'];
  if (before && after && fields.every(field => before[field] === after[field])) return;
  return updateCounter({ rounds: [before?.rodada, after?.rodada] });
});

exports.workroomCountOnProfile = watch('perfis/{uid}', (before, after) => {
  if (isEligible(before) !== isEligible(after)) return updateCounter();
});

exports.workroomCountOnRound = watch('config/estado', (before, after) => {
  const fields = ['rodada', 'themeId', 'fase', 'numSubmissoes'];
  if (after?.rodada && fields.some(field => before?.[field] !== after[field])) return updateCounter();
});

exports.workroomCountOnBeauty = watch('beauty_dinamicas/{round}', (before, after, { round }) => {
  if (beautyReleased(before) !== beautyReleased(after)) return updateCounter({ beautyRound: round });
});
