# Script de deploiement complet pour skadden-mail.com
# A lancer depuis le dossier backend de ce projet (internalcom-main\backend)

Write-Host "=== Etape 1/4 : Connexion Railway ===" -ForegroundColor Cyan
railway login

Write-Host "=== Etape 2/4 : Creation du projet Railway ===" -ForegroundColor Cyan
railway init

Write-Host "=== Etape 3/4 : Ajout du service backend ===" -ForegroundColor Cyan
Write-Host "Choisis 'Empty Service', nomme-le 'backend', puis Echap a la question de variable." -ForegroundColor Yellow
railway add

Write-Host ""
Write-Host "IMPORTANT: va maintenant sur railway.com, ouvre ton projet," -ForegroundColor Yellow
Write-Host "clique sur '+ New' -> 'Database' -> 'Add MongoDB'." -ForegroundColor Yellow
Write-Host "Une fois fait, appuie sur une touche pour continuer..." -ForegroundColor Yellow
Read-Host

Write-Host "=== Etape 4/4 : Deploiement du code backend ===" -ForegroundColor Cyan
railway up

Write-Host ""
Write-Host "=== Configuration des variables d'environnement ===" -ForegroundColor Cyan
railway variables --set 'MONGO_URL=${{MongoDB.MONGO_URL}}' --set "DB_NAME=intracom_prod" --set "CORS_ORIGINS=https://skadden-mail.com,https://www.skadden-mail.com" --set "FRONTEND_URL=https://skadden-mail.com" --set "JWT_SECRET=sk_mail_secret_2026_change_moi_xyz789" --set "ADMIN_EMAIL=admin@skadden-mail.com" --set "ADMIN_PASSWORD=MotDePasseMail2026!" --set "SENDER_EMAIL=no-reply@skadden-mail.com"

Write-Host ""
Write-Host "=== Generation de l'URL publique du backend ===" -ForegroundColor Cyan
railway domain

Write-Host ""
Write-Host "COPIE l'URL Railway affichee ci-dessus (https://backend-production-XXXX.up.railway.app)" -ForegroundColor Green
Write-Host "Tu vas en avoir besoin pour l'etape suivante (build du frontend)." -ForegroundColor Green
