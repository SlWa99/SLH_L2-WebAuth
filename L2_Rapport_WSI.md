# SLH L2 - Authentification
## Auteur : Slimani Walid
### Question 1 : *Les passkeys, comme l’authentification unique (SSO), permettent toutes deux à un utilisateur d’utiliser un seul mécanisme de sécurité pour tous ses services, sans s’exposer à une attaque de "credentials stuffing". Mais quelle est la différence en termes de risque?*



### Différence entre passkey et SSO en termes de risque

Les `passkeys` et les `SSO` ont des objectifs similiares mais l'approche qu'ils utilisent est différent ainsi que leurs implications en termes de risque.

**Passkeys :**

Avant de pouvoir identifier le problème, il faut bien comprendre le fonctionnement d'une passkey. Pour rappel, son fonctionnement est le suivant : Elles reposent sur une cryptographie asymétrique afin d'authentifier les utilisateurs. Une clé publique est stockée sur le serveur tandis que la clé privée reste sur l'appareil de l'utilisateur.

Le risque principal vient d'une compromission de l'appareil de l'utilisareur (ou directectement de la clé privée). Toutefois, les passkeys ne sont pas directement vulnérablles au `"credential stuffing"` ou au phising car aucun mot de passe n'est utilisé ou transmis.

En outre, même en cas de corruption du serveur les passkeys ne sont pas réutilisables ailleurs. La clé publique est unique au site.

**SSO : **

Avec le SSO, un utilisateur s'authentifie une seule fois au près d'un fournisseur d'identité et les services tiers délèguent cette authentification.

Le risque principale vient du fait que si le compte princiapal (au près du fournisseur d'identité) est compromis, l'attaquant obtient potentiellement accès à tous les services connectés. Le phishing est une menace très importante dans ce contexte car les utilisateurs peuvent être redirigés vers des faux sites d'authentification.

Toutefois, l'avantage du SSO est qu'il permet de centraliser la gestion des identifiants et réduit les risques liés à la réutilisation des mots de passe.

**Différence en termes de riseque :**

En outre, les passkeys offrents une protection plus forte contre le phishing et les attaques massivent comme le `"credentials stuffing"` car elles ne reposent pas sur des mots de passe ni sur un compte centralisé.

Un SSO est plus vulnérable en cas de compromission du fournisseur d'identité car il concentre les accès à différents services "dans un seul point".



### Question 2 : *Concernant la validation d’entrées pour les images, quelles sont les étapes que vous avez effec tuées? Et comment stockez vous les images?*



### Validation des entrées pour les images et méthodes de stockage des fichiers

**Validation des entées :**

Le code implémente plusieurs étapes pour valider les images uploadées garantissant à la fois la sécurité et l'intégrité des images stockées.

1) Verification du type

   Le type est extrait des métadonnées du fichier uploadé et validé afin de s'assurer qu'il correspond à une image au format `JPEG`.

   ```rust
   if mime.type_() != mime::IMAGE || (mime.subtype() != mime::JPEG) {
       return Err((StatusCode::BAD_REQUEST, "Only .jpg files are allowed").into());
   }
   ```

2. Validation du contenu du fichier

   En complément de la vérification du type, le contenu binaire du fichier est analysé. Cette étape permet de garentir que le fichier est bien une image valide et non un fichier "malveillant déguisé".

   ```rus
   let img = image::load_from_memory(file_bytes)
       .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid image file"))?;
   ```

3. Vérification des contraintes de taille et de dimensions

   Le code impose des limite sur la taille (pas demandé mais permet d'éviter des excès, il faut pas que les images prennent toute la place) et les dimensions de l'image pour éviter les abus tels que des fichiers très volumineux (éviter de saturer les ressources du serveur). Les limites sont les suivantes :

   - Taille maximale de 10 Mo
   - Dimension maximales de 500x500 pixels

   Si les contraintes ci-dessus ne sont pas respectées, le fichier est rejeté.

   ```rus
   if width > 500 || height > 500 || file_bytes.len() > 10 * 1024 * 1024 {
       return Err((StatusCode::BAD_REQUEST, "Image is too large. Max 500x500 pixels and 10MB").into());
   }
   
   ```

4. Vérification de la présence d'un texte associé :

   En plus de l'imafe, le code exige un champ texte qui est validé pour s'assurer qu'il est non vide et ne dépasse pas 200 caractères.

   ```rus
   if text.is_empty() || text.len() > 200 {
       return Err((StatusCode::BAD_REQUEST, "Text must be between 1 and 200 characters").into());
   }
   ```

**Stockage des images :**

Les images validées sont sauvegardées sur le serveur dans un répertoire dédié.

1. Création du répertoire de stockage :

   Le chemin du répertoire de stockage est défini dans une constante. Si ce répertoire n'existe pas, il est alors créé.

   ```rus
   let uploads_dir = consts::UPLOADS_DIR;
   if !Path::new(uploads_dir).exists() {
       create_dir_all(uploads_dir).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create upload directory"))?;
   }
   ```

2. Génération d'un nom de fichier unique :

   Pour éviter toute "collision" ou écrasement de fichiers existants, un nom unique est généré pour chaque image à l'aide d'un `UUID`. L'extension du fichier est extraite pour conserver le format originel.

   ```rus
   let unique_filename = format!("{}.{}", Uuid::new_v4(), file_extension);
   ```

3. Sauvegarde du fichier :

   Le fichier (l'image) est ensuite crée et les données sont écrites sur le disque. Le chemin du fichier est construit à l'aide du nom unique généré. Un chemin relatif est retourné pour être utilisé dans le Frontend.

   ```rust
   let file_path = format!("{}/{}", uploads_dir, unique_filename);
   let mut file = File::create(&file_path)
       .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create file"))?;
   file.write_all(&file_bytes)
       .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to write file"))?;
   ```



### Question 3 : *Que pensez-vous de la politique de choix des noms de fichiers uploadés? Y voyez-vous une vulnérabilité? Si oui, suggérez une correction.*



### Analyse de la politique actuelle

Actuellement, la politique de nommage des images repose sur la génération d'un `UUID` unique associé à l'extension extraite du fichier uploadé par l'utilisateur. Bien que cela permet d'obtenir des noms uniques, cette méthode présente une vulnérabilité potentielle liée à une attaque de type `Path Transversal`.

Le rsique principal réside dans l'utilisation du nom de fichier fourni par l'utilisateur pour générer le chemin final. Un attaquant pourrait exploiter cette dépendance en soumettant un nom de fichier malveillant contnant des séquences de traversée de répertoire telles que `../../../etc/passwd` ou encore `C:\Windows\systems32\cmd.exe`.

Bien que les `UUID` réduse parteillement ce risque, un nom malveillant pourrait entrainer les évènements suivants :

1. Ecriture de fichiers en degros du répertoire prévu :

   Si des chemins relatifs comme `../../` ou absolu sont interprétés par le système, un fichier pourrait être enregistré en dehors de l'arborescence sécurisée (c-à-d "uploads_dir").

2. Ecrasement de fichiers critiques :

   Si un fichier est enregistré dans un emplacement sensible, il pourrait pertruber le fonctionnement du serveur ou introduire des vulnérablités supplémentaires.

Selon les bonnes pratiques, il faudrait nettoyer le nom du fichier fourni et valider le chemin final généré.

En outre, la politique actuelle de nommage avec les `UUID` est globalement robuste pour éviter les collisions. Cependant, sans un nettoyage approprié du nom fourni par l'utilisateur et une validation stricte du chemin final, elle reste vulnérable aux attaques de type `Path Transversal`.