# 🚀 PENNY LANE CONVERTER - WebApp SaaS

## Architecture Complète pour Comptables

### Stack Tech (Coûts minimaux)
- **Backend**: FastAPI (Python) + Render (7€/mois)
- **Frontend**: React + Tailwind + Vercel (Gratuit)
- **Database**: Supabase PostgreSQL (Gratuit tier)
- **Storage**: Backblaze B2 (3€/mois)
- **Email**: Mailgun (Gratuit 100/jour)

### **TOTAL: ~10€/mois**

---

## 📋 ROADMAP

### Phase 1: MVP (Semaine 1-2)
- [ ] Backend FastAPI avec auth JWT
- [ ] Upload PDF + traitement
- [ ] Download Excel
- [ ] Database PostgreSQL
- [ ] Frontend React simple

### Phase 2: Monétisation (Semaine 3-4)
- [ ] Système de plans (Free/Starter/Pro)
- [ ] Payment Stripe integration
- [ ] Dashboard utilisateur
- [ ] Analytics

### Phase 3: Scalabilité (Semaine 5+)
- [ ] Support +10 banques
- [ ] API webhooks
- [ ] Intégration Penny Lane
- [ ] Mobile app

---

## 🔐 SÉCURITÉ
- JWT tokens + refresh
- Rate limiting
- File validation
- Password hashing (bcrypt)
- CORS configuration

---

## 💻 DÉPLOIEMENT GRATUIT/PAS CHER

### Backend (Render)
1. Fork repo sur GitHub
2. Deploy sur Render.com (gratuit ou 7€/mois)
3. Variables d'env Supabase

### Frontend (Vercel)
1. Deploy automatique depuis GitHub
2. Custom domain (gratuit sur Vercel)

### Database (Supabase)
1. Signup gratuit
2. 500MB storage inclus
3. Scalable sous demande

---

## 📊 BUSINESS MODEL

**Revenue = Subscriptions**

| Plan | Prix | Quota |
|------|------|-------|
| Free | 0€ | 5 PDFs/mois |
| Starter | 9€/mois | 100 PDFs + priorité |
| Pro | 29€/mois | Illimité + API |
| Enterprise | Custom | Custom |

**Projection:**
- 500 comptables × 29€ = **14,500€/mois** (potentiel)

---

**Status**: Prêt pour développement full-stack
**Next**: Créer backend FastAPI complet + frontend React
