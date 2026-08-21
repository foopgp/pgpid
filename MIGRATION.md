# Migration de `bl-pgpid` et `bl-pgpkey` vers `pgpid-mip`

*Plan préparé le 2026-08-21. À amender : c'est une proposition d'ordre, pas un
engagement de contenu.*

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
