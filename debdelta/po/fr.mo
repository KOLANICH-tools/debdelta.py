��    H      \  a   �         $  !  �   F  L   �     7  0   E  %   v  1   �     �  ?   �  	   $	     .	     D	     Y	     k	  /   �	     �	  ?   �	     
  &   &
  /   M
  1   }
  "   �
  5   �
  >     ,   G  4   t  >   �  '   �  )     %   :     `  $   �  #   �  >   �       	   "     ,     J     g  '   �  "   �  .   �  7   �  ,   3     `     x  A   �  .   �  9   �     3     M     f     z  �  �  �   t     �  D     9   ]  #   �  V   �  �        �     �     �  K   �       ]   3     �  2   �  P   �     (  �  5  �  �  �   �  O   i  !   �  6   �  )     7   <     t  F   �     �     �     �           3  4   T  %   �  G   �  &   �  -     9   L  :   �  ?   �  K     T   M  <   �  D   �  T   $  G   y  ?   �  9     ,   ;  -   h  5   �  ^   �     +      J   2   W   -   �   $   �   5   �   /   !  ;   C!  G   !  7   �!  "   �!     ""  W   :"  H   �"  I   �"     %#      D#  #   e#     �#  {  �#  �   $&  '   �&  G   '  C   K'  2   �'  �   �'  �   H(  
   �(     �(     �(  T   )  H   k)  x   �)     -*  9   C*  [   }*     �*               '   B       A                        !   ;       )   @   2   1   5       H                                  E   -   8      6   #       /         F      &              
   %       9   ?      ,      0   7   4          C   "   :   *          =             3                    <   	               .   (   $   D   >      G                        +     -v         verbose (can be added multiple times)
--no-act    do not do that (whatever it is!)
 -d         add extra debugging checks
 -k         keep temporary files (use for debugging)
--gpg-home HOME
            specify a different home for GPG

See man page for more options and details.
  Proxy settings detected in the environment; using "urllib2" for downloading; but
  this disables some features and is in general slower and buggier. See man page. (Faulty delta. Please consider retrying with the option "--forensic=http" ). (hit any key) (prelink %(time).2fsec, %(size)dk, %(speed)dk/s) (script %(time).2fsec %(speed)dk/sec) (sources.conf does not provide a server for `%s') (unaccounted %.2fsec) Created,    time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s Creating: Delta is not present: Delta is not signed: Delta is too big: Delta-upgrade statistics: Deltas: %(present)d present and %(absent)d not, Downloaded head of %s. Downloaded, time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s Downloading head of %s... Error: --gpg-home `%s' does not exist. Error: `%s' does not seem to be a Debian delta. Error: `%s' does not seem to be a Debian package. Error: `%s' is not a regular file. Error: argument is not a directory or a regular file: Error: argument of --alt is not a directory or a regular file: Error: argument of --dir is not a directory: Error: argument of --forensicdir is not a directory: Error: argument of --old is not a directory or a regular file: Error: feature `%s' cannot be disabled. Error: option `%s' is unknown, try --help Error: output format `%s' is unknown. Error: testing of delta failed: Error: the file `%s' does not exist. Failed! Safe upgrading APT cache... Faulty delta. Please send by email to %s the following files:
 Initializing APT cache... Lookup %s Need 3 filenames; try --help. Need a filename; try --help. Need to get %s of deltas. Not enough disk space for storing `%s'. Not enough disk space to download: Now invoking the mail sender to send the logs. Patching done, time %(time).2fsec, speed %(speed)dk/sec Recreated debs are saved in the directory %s Sending logs to server. Server answers: Sorry, cannot find an URI to download the debian package of `%s'. Sorry, no source is available to upgrade `%s'. Sorry, the package `%s' is already at its newest version. There were faulty deltas. Total running time: %.1f Upgraded APT cache. Upgrading APT cache... Usage: debdelta [ option...  ] fromfile tofile delta
  Computes the difference of two deb files, from fromfile to tofile, and writes it to delta

Options:
--signing-key KEY
            gnupg key used to sign the delta
--no-md5    do not include MD5 info in delta
--needsold  create a delta that can only be used if the old deb is available
 -M Mb      maximum memory  to use (for 'bsdiff' or 'xdelta')
--delta-algo ALGO
            use a specific backend for computing binary diffs
 Usage: debpatch-url [package names]
  Show URL wherefrom to downloads all deltas that may be used to upgrade the given package names
 WARNING, delta is not signed: Warning, no --old arguments, debdeltas will not generate any deltas. Warning, no non-option arguments, debdeltas does nothing. You may wish to rerun, to get also: delta is %(perc)3.1f%% of deb; that is, %(save)dkB are saved, on a total of %(tot)dkB. delta time %(time).2f sec, speed %(speed)dkB /sec, (%(algo)s time %(algotime).2fsec speed %(algospeed)dkB /sec) (corr %(corrtime).2f sec) done. downloaded debs,  downloaded deltas,  downloaded so far: time %(time).2fsec, size %(size)s, speed %(speed)4s/sec. failed! trying safe-upgrade... not enough disk space (%(free)dkB) in directory %(dir)s for applying delta (needs %(size)dkB) patching to debs,  size %(size)s time %(time)dsec speed %(speed)s/sec total resulting debs, size %(size)s time %(time)dsec virtual speed %(speed)s/sec upgrading... Project-Id-Version: debdelta
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2017-01-07 18:04+0100
PO-Revision-Date: 2012-08-02 23:25+0200
Last-Translator: Thomas Blein <tblein@tblein.eu>
Language-Team: French <debian-l10n-french@lists.debian.org>
Language: fr
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Generator: Lokalize 1.4
Plural-Forms: nplurals=2; plural=(n > 1);
  -v         verbosité (peut être utilisé plusieurs fois)
--no-act    ne pas effectuer l'action (quelle qu'elle soit !)
 -d         ajouter des vérifications de débogage supplémentaires
 -k         garder les fichiers temporaires (utilisés à des fins de
            débogage)
--gpg-home HOME
            indiquer un répertoire personnel différent pour GPG

Consultez la page de manuel pour plus d'option et de détails.
 Configuration de proxy détectée dans l'environnement ; utilisation de « urllib2 » pour le téléchargement ; mais cela désactive certaines caractéristiques et c'est généralement plus lent. Consultez la page de manuel. (Delta défectueux. Veuillez réessayer avec l'option « --forensic=http »). (Pressez n'importe quelle touche) (prelink %(time).2f sec, %(size)d k, %(speed)d k/s) (script %(time).2f sec %(speed)d k/sec) (sources.conf ne fournit aucun serveur pour « %s ») (inexpliqué %.2f sec) Créé,       temps %(time)5.2f sec, vitesse %(speed)4s/sec, %(name)s Création : Le delta est absent : Le delta n'est pas signé : Le delta est trop important : Statistiques de delta-upgrade : Deltas : %(present)d présent et %(absent)d absent, En-tête du fichier %s téléchargé. Téléchargé, temps %(time)5.2f sec, vitesse %(speed)4s/sec, %(name)s Téléchargement de l'entête de %s… Erreur : --gpg-home « %s » n'existe pas. Erreur : « %s » ne semble pas être un delta Debian. Erreur : « %s » ne semble pas être un paquet Debian. Erreur : le fichier « %s » n'est pas un fichier classique. Erreur : le paramètre n'est pas un répertoire ou un fichier classique : Erreur : le paramètre de --alt n'est pas un répertoire ou un fichier classique : Erreur : le paramètre de --dir n'est pas un répertoire : Erreur : le paramètre de --forensicdir n'est pas un répertoire : Erreur : le paramètre de --old n'est pas un répertoire ou un fichier classique : Erreur : la fonctionnalité « %s » ne peut pas être désactivée. Erreur : l'option « %s » n'est pas connue. Essayez --help. Erreur : le format de sortie « %s » n'est pas connu. Erreur : les tests de delta ont échoué : Erreur : le fichier « %s » n'existe pas. Échec ! Mise à niveau conservative du cache APT… Delta défectueux. Veuillez envoyer par courrier électronique à %s les fichiers suivants :
 Initialisation du cache APT… Recherche %s Besoin de trois noms de fichier ; essayez --help. Besoin d'un nom de fichier ; essayez --help. Besoin de récupérer %s des deltas. Pas assez d'espace disque pour enregistrer « %s » Pas assez d'espace disque pour télécharger : Invocation de l'envoyeur de mail pour envoyer les journaux. Correction effectuée, temps %(time).2f sec, vitesse %(speed)d k/sec. Les debs recréés sont sauvés dans le répertoire %s. Envoi des journaux sur le serveur. Réponses du serveur : Désolé, impossible de trouver une URI pour télécharger le paquet debian « %s ». Désolé, aucune source disponible pour la mise à niveau de « %s ». Désolé, le paquet « %s » est déjà à la version la plus récente. Il y a des deltas défectueux. Temps d'exécution total : %.1f Le cache APT a été mis à niveau. Mise à niveau du cache APT… Usage : debdelta [OPTION] FICHIER_ORIGINE FICHIER_DESTINATION DELTA
  Calcule la différence entre deux fichiers deb, entre FICHIER_ORIGINE et FICHIER_DESTINATION, et l'inscrit dans DELTA.

Options :
--signing-key CLÉ
            clé gnupg à utiliser pour signer la différence
--no-md5    ne pas inclure les informations MD5 de la différence
--needsold  créer un delta qui ne peut être utilisé que si le vieux deb
            est disponible
 -M Mb      mémoire maximum à utiliser (pour 'bsdiff' ou 'xdelta')
--delta-algo ALGO
            utilise une dorsale spécifique pour calculer les différences 
            binaires
 Usage : debpatch-url [NOMS_DE_PAQUET]
  Afficher l'URL utilisée pour le téléchargement de tous les deltas qui peuvent être utilisés pour mettre à jour les paquets précisés.
 ATTENTION, le delta n'est pas signé : Attention, aucun paramètre --old, debdeltas ne générera aucun delta. Attention, aucun paramètre non-option, aucune action de debdeltas. Vous pourriez relancer, pour obtenir également : Le delta a une taille de %(perc)3.1f %% du deb ; c'est-à-dire que %(save)d kB ont été économisés sur un total de %(tot)d kB. delta temps %(time).2f sec, vitesse %(speed)d kB/sec, (%(algo)s temps %(algotime).2f sec vitesse %(algospeed)d kB/sec) (corr %(corrtime).2f sec) Effectué. debs téléchargé,  deltas téléchargés,  déjà téléchargé : %(time).2f sec, taille %(size)s, vitesse de %(speed)4s/sec. Échec ! Essai d'une mise à niveau conservative (« safe-upgrade ») pas assez d'espace disque (%(free)d kB) dans le répertoire %(dir)s pour appliquer les deltas (besoin de %(size)d kB). correction des debs,  taille %(size)s temps %(time)d sec vitesse %(speed)s/sec debs résultant totaux, taille %(size)s temps %(time)d sec vitesse virtuelle %(speed)s/sec mise à niveau… 