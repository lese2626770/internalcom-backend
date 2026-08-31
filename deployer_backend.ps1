# Deploiement backend generique - fonctionne pour n'importe quel nouveau domaine.
# Usage : powershell -ExecutionPolicy Bypass -File .\deployer_backend.ps1 -Domaine "tondomaine.com" -MotDePasseAdmin "UnBonMotDePasse123!"

param(
    [Parameter(Mandatory=$true)]
    [string]$Domaine,
    [Parameter(Mandatory=$true)]
    [string]$MotDePasseAdmin,
    [string]$AdminEmail = "",
    [string]$ResendApiKey = ""
)

if ($AdminEmail -eq "") { $AdminEmail = "admin@$Domaine" }

Write-Host "=== Etape 1/6 : Connexion Railway ===" -ForegroundColor Cyan
railway login

Write-Host "=== Etape 2/6 : Creation du projet Railway ===" -ForegroundColor Cyan
railway init

Write-Host "=== Etape 3/6 : Ajout du service backend ===" -ForegroundColor Cyan
Write-Host "IMPORTANT: choisis 'Empty Service', nomme-le EXACTEMENT 'backend', puis Echap a la question de variable." -ForegroundColor Yellow
railway add

Write-Host "=== Etape 4/6 : Ajout de MongoDB (meme service Railway) ===" -ForegroundColor Cyan
Write-Host "IMPORTANT: choisis 'Database' puis 'MongoDB' pour l'ajouter DANS CE MEME PROJET." -ForegroundColor Yellow
railway add

Write-Host "=== Etape 5/6 : Deploiement du code + variables ===" -ForegroundColor Cyan
railway up

$jwtSecret = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | ForEach-Object {[char]$_})

railway variables --set "DB_NAME=intracom_prod" --set "CORS_ORIGINS=https://$Domaine,https://www.$Domaine" --set "FRONTEND_URL=https://$Domaine" --set "JWT_SECRET=$jwtSecret" --set "ADMIN_EMAIL=$AdminEmail" --set "ADMIN_PASSWORD=$MotDePasseAdmin" --set "SENDER_EMAIL=no-reply@$Domaine"

if ($ResendApiKey -ne "") {
    railway variables --set "RESEND_API_KEY=$ResendApiKey"
}

Write-Host ""
Write-Host "=== IMPORTANT: connecter MongoDB manuellement ===" -ForegroundColor Red
Write-Host "Le nom du service MongoDB varie a chaque fois (ex: mongodb-volume, MongoDB...)." -ForegroundColor Yellow
Write-Host "1. Va sur le dashboard Railway (railway.app), ouvre ton projet." -ForegroundColor Yellow
Write-Host "2. Clique sur le service MongoDB -> onglet Variables -> copie la valeur de MONGO_URL (ou MONGO_PUBLIC_URL)." -ForegroundColor Yellow
Write-Host "3. Reviens ici et lance :" -ForegroundColor Yellow
Write-Host "   railway variables --set `"MONGO_URL=la_valeur_copiee`"" -ForegroundColor Green
Write-Host ""
Write-Host "Appuie sur une touche une fois MONGO_URL configure pour generer l'URL publique du backend..." -ForegroundColor Yellow
Read-Host

Write-Host "=== Etape 6/6 : Generation de l'URL publique ===" -ForegroundColor Cyan
railway domain

Write-Host ""
Write-Host "=== TERMINE ===" -ForegroundColor Green
Write-Host "Copie l'URL Railway ci-dessus (https://backend-production-XXXX.up.railway.app)." -ForegroundColor Green
Write-Host "Tu en as besoin pour l'etape suivante : deployer_frontend.ps1" -ForegroundColor Green
