#!/bin/bash

# 0 - Ajout du plugin Post Fonction => à appeler une fois à la création
 curl -i -X POST http://<admin-api>/CACF/services/<my-service>/plugins \
     -F "name=post-function" \
     -F "config.access[1]=@function-call-APIKeyValidationService.lua" \
     -H "Kong-Admin-Token: <to-be-changed>"

# 1 - Mise à jour du plugin Post Fonction => à appeler à chaque mise à jour
curl -i -X PATCH http://<admin-api>/CACF/plugins/<plugin-id-retrieved-above> \
     -F "config.access[1]=@function-call-APIKeyValidationService.lua" \
     -H "Kong-Admin-Token: <to-be-changed>"