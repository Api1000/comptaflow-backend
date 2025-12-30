# 📋 GUIDE D'INSTALLATION - SYSTÈME DE VALIDATION BANCAIRE

## 📦 Fichiers fournis

1. **bank_detector.py** - Module de détection et validation
2. **backend_validation_endpoints.py** - Code à ajouter au backend
3. **StatementValidator.jsx** - Composant React frontend
4. **requirements.txt** - Dépendances Python

## 🔧 INSTALLATION BACKEND

### 1. Installer les dépendances Python

```bash
pip install PyPDF2
```

### 2. Ajouter bank_detector.py

Placez le fichier `bank_detector.py` dans le dossier racine de votre backend
(même niveau que `backend-main.py`)

### 3. Modifier backend-main.py

Ouvrez `backend-main.py` et ajoutez les imports en haut du fichier :

```python
from bank_detector import validate_statement, count_transactions, get_supported_banks
import PyPDF2
from io import BytesIO
```

### 4. Copier les endpoints

Copiez tout le contenu de `backend_validation_endpoints.py` dans votre `backend-main.py`
(à la fin du fichier, avant les routes de test si elles existent)

### 5. Créer la table Supabase (optionnel)

Pour le signalement des banques non supportées :

```sql
CREATE TABLE unsupported_banks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    bank_name TEXT NOT NULL,
    user_email TEXT,
    reported_at TIMESTAMP DEFAULT NOW()
);
```

### 6. Tester le backend localement

```bash
uvicorn backend-main:app --reload
```

Testez l'endpoint :
```bash
curl http://localhost:8000/supported-banks
```

### 7. Déployer sur Render

```bash
git add bank_detector.py backend-main.py
git commit -m "Add bank validation system"
git push origin main
```

Render redéploiera automatiquement.

## 🎨 INSTALLATION FRONTEND

### 1. Ajouter StatementValidator.jsx

Placez `StatementValidator.jsx` dans `src/components/`

### 2. Ajouter la route dans App.jsx

```jsx
import StatementValidator from './components/StatementValidator';

// Dans vos routes
<Route 
  path="/validate" 
  element={isAuthenticated ? <StatementValidator /> : <Navigate to="/login" />} 
/>
```

### 3. Ajouter un lien dans le Dashboard/Menu

```jsx
<Link to="/validate" className="...">
  Vérifier la compatibilité
</Link>
```

### 4. Tester localement

```bash
npm run dev
```

Allez sur http://localhost:5173/validate

### 5. Déployer sur Vercel

```bash
git add .
git commit -m "Add statement validator component"
git push origin main
```

Vercel redéploiera automatiquement.

## 🧪 TESTS

### Test 1 : Validation d'un relevé LCL

1. Allez sur `/validate`
2. Uploadez un des relevés LCL fournis
3. Vérifiez que la banque est détectée comme "LCL - Crédit Lyonnais"
4. Vérifiez le message "✅ Relevé compatible"

### Test 2 : Validation Crédit Agricole

1. Uploadez un relevé CA
2. Vérifiez la détection "Crédit Agricole"

### Test 3 : Validation Banque Populaire

1. Uploadez un relevé BP
2. Vérifiez la détection "Banque Populaire"

### Test 4 : Relevé non supporté

1. Uploadez un PDF quelconque (pas un relevé)
2. Vérifiez le message "Banque non reconnue"
3. Cliquez sur "Signaler ma banque"

## 📊 MONITORING

### Backend logs

Sur Render, allez dans l'onglet "Logs" et cherchez :

```
Validation statement - User: xxx@xxx.com, Bank: LCL, Compatible: True
```

### Frontend console

Dans la console du navigateur, vérifiez les appels API :

```
POST /validate-statement
Response: { compatible: true, bank: "LCL", ... }
```

## 🚀 PROCHAINES ÉTAPES

1. ✅ Tester avec vos 3 banques actuelles
2. ✅ Collecter les signalements d'utilisateurs
3. ✅ Ajouter de nouvelles banques selon la demande
4. ✅ Améliorer les patterns de détection si nécessaire

## 🆘 DÉPANNAGE

### "Module 'bank_detector' not found"
→ Assurez-vous que `bank_detector.py` est au bon endroit

### "No module named 'PyPDF2'"
→ Installez avec `pip install PyPDF2`

### "404 Not Found" sur /validate-statement
→ Vérifiez que le backend est redéployé avec les nouveaux endpoints

### Le composant ne s'affiche pas
→ Vérifiez la route dans App.jsx et le chemin d'import

## 📧 SUPPORT

En cas de problème, vérifiez :
1. Les logs backend sur Render
2. La console du navigateur (F12)
3. Que les variables d'environnement sont bien configurées
