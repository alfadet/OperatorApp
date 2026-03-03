# OperatorApp — AD Security Gestione Operatori

App web per la gestione degli operatori di sicurezza.

## Struttura

```
OperatorApp/
├── index.html              # App principale
├── libs/                   # Librerie JS (offline)
│   ├── jspdf.umd.min.js
│   ├── jspdf.plugin.autotable.min.js
│   └── xlsx.full.min.js
├── nginx/
│   └── operatorapp.conf    # Config nginx per VPS
├── deploy.sh               # Script deploy automatico
└── README.md
```

## Deploy su VPS Hostinger

### Requisiti
- VPS con Ubuntu 20.04/22.04
- Dominio puntato al VPS

### Passi

1. **Clona il repo sul VPS:**
   ```bash
   git clone https://github.com/alfadet/OperatorApp.git
   cd OperatorApp
   ```

2. **Modifica il dominio nello script:**
   ```bash
   nano deploy.sh  # cambia "tuodominio.com" con il tuo dominio
   nano nginx/operatorapp.conf  # stesso
   ```

3. **Esegui il deploy:**
   ```bash
   chmod +x deploy.sh
   sudo bash deploy.sh
   ```

## Google Drive (opzionale)

Per abilitare il backup su Google Drive:
1. Vai su [console.cloud.google.com](https://console.cloud.google.com)
2. Crea un progetto → abilita Google Drive API
3. Crea credenziali OAuth 2.0
4. Inserisci il Client ID nell'app (sezione Impostazioni → Google Drive)

## Database

L'app usa **localStorage** del browser — nessun database server necessario.
I dati vengono salvati localmente nel browser dell'utente.
