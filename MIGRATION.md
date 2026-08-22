# Migration de `bl-pgpid` et `bl-pgpkey` vers `pgpid`

*Plan préparé le 2026-08-21, exécuté du 21 au 22 août. Conservé comme compte
rendu : ce qui a été vérifié, comment, et ce qui a été fait autrement à
dessein.*

L'outil s'est appelé **`pgpid`** pendant la migration — *mip* pour
« migration in progress » — et vivait dans le dépôt de foodjis. Le 22 août il
est arrivé ici sous son nom, `pgpid`. Le texte ci-dessous dit `pgpid` partout ;
les commits d'avant cette date disent l'autre nom.

Vingt-et-une actions, environ 2 900 lignes de bash. Sept sont déjà passées :
`list`, `property` (lecture), `sigs`, `ownertrust`, `del`, `avatar`, `push`.

## Le critère qui décide de l'ordre

Sur Android il n'y a **ni bash ni gpg**. Ce qui s'y porte n'est donc pas le
code, c'est l'intention — et une intention se porte d'autant mieux qu'elle est
écrite sans dépendre du comportement de gpg. D'où le classement suivant, mesuré
et non supposé :

| classe | actions | ce que le portage coûtera |
|---|---|---|
| **logique pure** — aucun appel à gpg | `gen_u4`, `mrz_to_u4`, `gen_uid`, `to_vcard` | presque rien : le C est déjà la spécification |
| lecture par gpg | `get`, `list`, `property`, `sigs`, `cert_check` | moyen : requêtes à rejouer sur une autre bibliothèque |
| écriture par gpg | `email`, `certify`, `gen_key`, `update_trustdb`, `avatar` | élevé : séquences d'édition à réécrire |
| pilotage de la carte | `token_check`, `totoken`, `change_token_meta` | élevé et différent : NFC/USB, pas scdaemon |
| rendu | `print_card`, `print_secret`, `scan` | moyen : images et QR codes, dépendances tierces |

**Conséquence pratique** : commencer par la logique pure n'est pas un
échauffement, c'est le seul endroit où le travail se paie deux fois. Ces
quatre actions sont d'ailleurs **déjà dupliquées** — les motifs d'eid de
`src/eid.c` sont un port caractère par caractère des `BL_PGPID_*_REGEX`. La
vague 1 supprime une duplication existante au lieu d'en ajouter une.

## Vague 0 — fermer ce qui est ouvert

Aucune action nouvelle, seulement des équivalences à établir.

- **`list --short`** — sortie strictement équivalente à `bl-pgpid get
  --no-fetch`.
- **`get`** — même chose mais **l'argument est obligatoire**, `'*'` valant
  « tout ». La différence est voulue : `list` montre, `get` cherche, et une
  recherche sans motif est probablement une erreur de l'appelant.
- **`cert_check` n'existera pas.** `list` le remplace avantageusement — il
  répond davantage pour moins cher (140 ms contre 28,4 s sur 128 certificats).
  À dire explicitement dans le manuel, parce que l'absence d'une commande
  attendue se lit autrement comme un oubli.

## Vague 1 — la logique pure (≈ 280 lignes)

`gen_u4` · `mrz_to_u4` · `gen_uid` · `to_vcard`

Aucun appel à gpg, aucune écriture, aucune carte : le risque est nul et le
bénéfice est double (Android, et fin de la duplication des motifs d'eid).
`gen_uid` est en outre appelée par `gen_key` et `email` — la faire d'abord
évite de la porter deux fois.

## Vague 2 — lire la carte

`token_check` · `token_retries`

Le chemin le plus chaud de foodjis : appelé à chaque branchement, et deux fois
(rapide sans réseau, puis lent avec). Lecture seule — on ne touche pas encore
à ce que la carte contient.

**Faite.** Sortie identique au shell sur la carte branchée, dans les deux
formes (avec et sans interrogation des serveurs de clés) ; 2 744 → 1 793 ms
pour cinq appels de la forme chaude, l'écart restant modeste parce que c'est
la latence de la carte qui domine, pas l'interpréteur.

Le décompte des champs manquants — les codes 101 à 107 — ne peut pas être
atteint avec une carte complète. Il a été provoqué en retirant des lignes de
la réponse de `--card-status` : mêmes codes, mêmes champs, dans le même ordre.
Retirer le nom du porteur ne manque rien, des deux côtés, parce que
`pgpid_name` vient du certificat et non de la carte.

Deux différences assumées : l'identifiant est lu dans « Login data », que la
carte écrit nu, là où le lecteur d'uid attendait ses enrobages ; et la ligne
finale `Info:` est reformulée, foodjis ne l'affichant jamais (il ne montre
stderr qu'au-delà de 101).

## Ce qui manque encore : les messages ne sont pas traduits

`token_check` a montré un manque qui vaut pour tout pgpid. Ses lignes
`Notice:` ne sont pas de la prose interne : foodjis les affiche telles quelles
à qui branche une clé refusée. Côté shell elles passent par gettext ; côté C
il n'y a pas de gettext du tout, et une centaine de messages sont en anglais
seul. Un utilisateur francophone verrait donc, après migration, une phrase
anglaise là où il lisait une phrase française.

Ce n'est pas propre à cette vague et ça ne se répare pas dedans. À trancher
avant que foodjis n'appelle pgpid sur ce chemin : soit `libintl` et un
domaine à nous, soit les manuels traduits mais les messages non — ce qui est
un choix, pas un oubli, et se dit alors quelque part.

## Vague 3 — écrire dans le certificat

`property` (écriture) · `email` · `certify` · `update_trustdb`

La machinerie existe déjà : la conversation d'édition écrite pour `avatar` est
en place et testée, avec ses deux pièges documentés (la question est dans
`args`, et un contexte ne porte qu'une opération). C'est ici que la dépendance
de foodjis au bash tombe pour de bon : `email` et `certify` sont les deux
appels qui restent.

**Attention particulière** : `certify` et la révocation d'un uid sont
irréversibles. Même règle que pour `del` et `push` — empreinte obligatoire,
jamais un motif de recherche.

**Faite.** Éprouvée sur un trousseau jetable de quatre certificats, remis à
neuf avant chaque essai, sans qu'aucun serveur de clés soit nommé. Une
quarantaine de cas : signature, révocation, `--all-emails`, `--local`,
`--ownertrust`, ajout et révocation d'adresses et de propriétés,
`--revoke-all`, les échappements RFC 6350 avec virgules et points-virgules,
le serveur préféré écrit puis relu par l'autre outil, et la chaîne de
délégations signées. Mêmes codes de retour, mêmes sorties, même état du
trousseau.

Le décompte des champs manquants et les branches d'erreur ne s'atteignent pas
avec un trousseau sain ; elles ont été provoquées — empreinte inconnue,
identité absente, dernière adresse, délégation non signée, délégation qui
prétend redéfinir la confiance en nos propres clés. Cette dernière est la
seule qui compte vraiment : l'ancre tient des deux côtés.

Là où le shell ouvre une fenêtre, le C dit quoi passer à la place. La phrase
sur l'irréversibilité d'une révocation est écrite plutôt que sautée : c'est le
seul endroit où quelqu'un l'apprend.

### Deux défauts trouvés en chemin

`property` rendait 141 quand la propriété était simplement vide. Foodjis
*« fait remonter tout code non nul plutôt que de l'avaler »* — un contact sans
numéro de téléphone serait devenu une erreur. 141 vaut pour « aucun certificat
trouvé », pas pour « ce certificat n'a pas de téléphone ». Corrigé.

L'affichage de `property` passait par gpgme, qui ne sait pas distinguer un uid
expiré d'un uid que personne n'a certifié : `--show-unusable` n'avait donc
rien à montrer. Il lit maintenant la sortie à deux points, comme le shell.

### Un défaut partagé, laissé en l'état

`property lang --add français` est accepté des deux côtés. `[a-zA-Z]` dépend
de la collation de la locale, et sous une locale française la plage couvre les
lettres accentuées — en bash comme dans `regcomp`. Le C reproduit donc
fidèlement le défaut du shell. À corriger dans les deux, ou dans aucun : ce
n'est pas à la migration de trancher.

## Vague 4 — la carte et le papier

`gen_key` · `totoken` · `change_token_meta` · `change_token_code` ·
`change_passphrase` · `print_card` · `print_secret` · `scan`

En dernier, pour trois raisons : ce sont les plus destructrices, les plus liées
à scdaemon, et **les moins portables de toute façon** — sur Android la carte se
parle en NFC, pas par un démon.

Deux renommages à faire à ce moment-là, puisque les deux bibliothèques ont une
action `print` et qu'elles n'impriment pas la même chose :

- `bl_pgpid_print` → **`print_card`** — « produce or print a PGP ID stamp or
  business card ».
- `bl_pgpkey_print` → **`print_secret`** — la clé secrète en QR codes.

Le nom dit alors lequel des deux ne doit **jamais** partir sur une imprimante
partagée, ce que `print` ne disait pas.

**Faite, à une réserve près qui compte** — voir plus bas.

`gen_key` produit les mêmes uids dans le même ordre, avec les mêmes sous-clés,
la même expiration, le même serveur préféré et la même note échappée.
`change_passphrase` a été vérifiée en vidant le cache de l'agent entre chaque
essai : sans cela la signature réussit avec l'ancienne phrase et l'essai ne
prouve rien. `print_card` rend un SVG identique à l'octet sur toutes les
formes.

Le papier se relit **dans les deux sens** : trois fragments imprimés par le C
reconstruisent la clé sous `bl-pgpkey scan`, et trois fragments imprimés par
le shell la reconstruisent sous `pgpid scan`. C'est la seule vérification
qui vaille pour une sauvegarde — celle que personne n'a jamais restaurée n'est
pas une sauvegarde.

Le TODO est fait : les photos ne partent plus à l'imprimante. Sur un
certificat qui en porte une, l'export passe de 2 566 à 1 239 octets — la
moitié du papier à conserver en moins. Les uids sont en revanche **tous
gardés** : « extras uid » est ambigu, et une sauvegarde qui perd un numéro de
téléphone est une sauvegarde qui a perdu quelque chose. À trancher.

### Le papier ne garde que trois uids

Demandé par JJB le 22 août, et la mesure lui donne plus raison qu'il ne le
pensait : ce n'est pas une question de lisibilité, c'est une question de
possibilité. Un QR code au niveau L porte 2 953 octets au maximum.

| ce qui est exporté | fragment | QR |
|---|---|---|
| tout, comme le shell aujourd'hui — 3 311 o | 4 416 o | **refusé, trop gros** |
| sans les photos — 1 984 o | 2 648 o | 169 modules de côté |
| sans les photos, trois uids — 1 239 o | 1 652 o | **137 modules** |

Autrement dit, un certificat portant une photo et quelques propriétés ne
s'imprime **pas du tout** aujourd'hui. Les trois uids gardés sont l'identité
(`UID:urn:eid:`), le nom (`FN:`) et **une** adresse : celle de l'uid principal,
et à défaut la plus récente qui tienne encore. Le reste se retrouve dans
n'importe quel trousseau.

Le retrait se fait au niveau des paquets : l'auto-signature d'un uid ne lie que
cet uid, donc jeter la paire laisse toutes les autres signatures aussi valides
qu'avant. Rien n'est resigné — donc rien ne réclame la phrase de passe et
aucune date ne change.

### Ce qui a été éprouvé sur une carte d'essai

JJB a branché une carte de rebut le 22 août. Les trois actions qui écrivent
dessus sont désormais vérifiées sur du matériel :

- **`totoken`** — reset d'usine, configuration, attributs de clé, transfert des
  trois sous-clés, tirage et pose des deux nouveaux codes. La clé locale est
  bien devenue un renvoi vers la carte. Lancée sur la **même clé** par les deux
  outils, elle laisse un **état de carte identique champ pour champ**.
- **`change_token_code`** — changement, vérification, et les trois codes de
  retour dans l'ordre : 194 puis 193 puis 192, jusqu'au blocage ; puis
  `--unblock` avec le code Admin, qui rend les trois essais et pose le nouveau
  PIN. Un code correct remet le compteur à plein.
- **`change_token_meta`** — les trois champs écrits et relus : la langue
  (trois fois de suite, sans faute), l'URL (acceptée quand le certificat servi
  porte les trois sous-clés, refusée sinon), et le nom (refusé pour une adresse
  que le certificat ne porte pas, et au-delà de 38 octets).

### Un défaut trouvé en éprouvant : « quel trousseau » n'avait pas une réponse

La lecture de la carte contournait `--homedir` : `--card-status` et
`gpg-connect-agent` étaient appelés nus. Conséquence, `totoken --homedir X`
détectait la carte depuis le trousseau **par défaut**, dont l'agent prenait
alors le lecteur — et `--card-edit`, lui, cherchait la carte dans X et trouvait
« aucun périphérique de ce type ». Un seul scdaemon tient le lecteur à la fois ;
demander sans dire quel trousseau en démarre un second. Tous les accès carte
passent maintenant par le trousseau nommé.

Corollaire pratique, qui coûte du temps quand on l'ignore : un scdaemon coincé
ne meurt pas sur SIGTERM et garde le périphérique. La carte devient alors
invisible depuis *tous* les trousseaux à la fois, ce qui ressemble à un
débranchement.

### Ce qui n'a pas pu être éprouvé

*Cette section n'a plus lieu d'être : la carte d'essai a levé la réserve.* Elle
reste ici pour mémoire de ce qui s'était passé entre-temps.

Une bêtise au passage, qui vaut mise en garde : comparer « ce qui refuse avant
la carte » a coûté un essai. Le shell ne refuse pas un code manquant, il le
*demande*, reçoit du vide, et vérifie quand même — le 194 que j'ai lu venait
de la carte. Compteur remis à 3 par une vérification correcte, après avoir
vidé le cache de scdaemon.

Deux différences assumées, du même genre que dans les vagues précédentes. Le C
ne demande jamais : `change_token_code` exige les deux codes d'entrée, ce qui
lui interdit par construction de dépenser un essai sur une commande
incomplète. Et `print_secret --printer ''` produit les feuilles sans rien
envoyer, comme `--keyservers ''` n'envoie à personne.

### Un défaut corrigé, trouvé en exécutant le refus

`totoken` retirait la phrase de passe de la clé **avant** de vérifier
`--force` : un refus modifiait donc quand même la clé sur le disque. Le shell
fait pareil. Le refus passe maintenant en premier.

**Un TODO devient presque gratuit ici** : *« Remove Photos and extras uid from
exported data »* (bl-pgpkey l. 742). L'export secret emporte aujourd'hui les
photos et toutes les adresses — un dos de papier qui porte votre visage, et
des QR codes plus nombreux que nécessaire. Le lecteur de paquets écrit pour
`avatar` sait déjà les reconnaître.

## Ce que deviennent les dépendances aux autres bash-libs

Vérifié fonction par fonction, code vivant seulement :

| appel | fournisseur | usages | devenir |
|---|---|---|---|
| `bl_input`, `bl_radiolist`, `bl_yesno` | bl-interactive | 29 | **replis**, pas dépendances : ils ne se déclenchent que si la commande est imprécise. En C : demander s'il y a un terminal, sinon échouer en `2`. |
| `bl_new_password` | bl-security | 3 | porte une intention — fabriquer un secret correct — qui garde son sens compilée |
| `bl_shred_path` | bl-security | 2 | idem : effacer pour de bon |
| `bl_shrink_num` | bl-security | 1 | logique pure, part avec la vague 1 |
| `bl_urandom` | bl-security | 2 | **disparaît** : `getrandom(2)` est là |
| `bl_log` | bl-log | **0** | plus de dépendance — l'unique occurrence est dans un commentaire |

## Avant de déménager dans le dépôt `pgpid`

La validation demandée, dans l'ordre où elle a du sens :

1. **Les vagues 1 à 3 passées** — foodjis n'appelle plus `bl-pgpid` ni
   `bl-pgpkey` que pour la carte et le papier.
2. **Les manuels, en neuf langues.** Les mêmes que le reste : allemand,
   anglais, espagnol, français, italien, polonais, portugais, russe,
   ukrainien.
3. **L'autocomplétion**, par action et par option.
4. **Puis seulement** : le code part dans `codeberg.org/foopgp/pgpid` sous le
   nom `pgpid`, et `bl-pgpid`/`bl-pgpkey` sont déclarées obsolètes.

Deux choses à annoncer ce jour-là, sinon elles se lisent de travers : le
binaire **change de nom**, et sa **version retombe** de la ligne 2.0.x —
empruntée à foodjis parce qu'il voyage dedans — à celle du paquet `pgpid`
(0.0.7 →).
