'use strict';
const path = require('path');
const fs = require('fs');
const f = path.join(__dirname, '..', '.env');
if (fs.existsSync(f)) process.loadEnvFile(f);
