��    P      �  k         �     �  $  �  �   �  L   �     �  0   �  %   -	  1   S	     �	  ?   �	  	   �	  !   �	     
     
     2
  *   D
  5   o
     �
  /   �
     �
  ?        F  &   `  /   �  1   �  "   �  5     >   B  ,   �  4   �  >   �  '   "  )   J  %   t     �  $   �  #   �  >        B  	   \     f     �     �  '   �  "   �  .     7   5  ,   m     �     �  A   �  .     9   3     m     �     �     �  �  �  �  �  /  m  �  �  �   e     �  D   	  9   N     �  #   �  V   �  �        �     �     �  K   �       ]   =     �  2   �  P   �     2  V  ?     �  I  �  �   �   P   �!     �!  0   "  %   F"  4   l"     �"  C   �"     �"  "   #     &#     @#     Y#  @   t#  J   �#       $  6   !$     X$  C   r$  !   �$  #   �$  /   �$  3   ,%  %   `%  <   �%  E   �%  2   	&  :   <&  E   w&  <   �&  4   �&  1   /'  %   a'      �'  3   �'  P   �'  &   -(     T(  0   ](  .   �(  %   �(  6   �(  0   )  R   K)  >   �)  ;   �)  "   *     <*  J   P*  ?   �*  5   �*     +     /+  $   B+  #   g+     �+  �  �-  �  T/  C  �3  {   ?6  $   �6  G   �6  F   (7     o7  1   �7  f   �7  �   "8     �8     �8     �8  U   �8  (   59  t   ^9     �9  =   �9  ]   :     |:     <   0   /   	             M                 -      ,   2           *                 +   .             F      1      #   8       7   I           P   G          L   K             $       B      "       '   N      :   O   5       ;   
      9           >         3   E   @               )       4   A      ?   H                        %   C   &       J   6   (   D   =                          !      Redirect to:  -v         verbose (can be added multiple times)
--no-act    do not do that (whatever it is!)
 -d         add extra debugging checks
 -k         keep temporary files (use for debugging)
--gpg-home HOME
            specify a different home for GPG

See man page for more options and details.
  Proxy settings detected in the environment; using "urllib2" for downloading; but
  this disables some features and is in general slower and buggier. See man page. (Faulty delta. Please consider retrying with the option "--forensic=http" ). (hit any key) (prelink %(time).2fsec, %(size)dk, %(speed)dk/s) (script %(time).2fsec %(speed)dk/sec) (sources.conf does not provide a server for `%s') (unaccounted %.2fsec) Created,    time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s Creating: Creation of delta failed, reason: Delta is not present: Delta is not signed: Delta is too big: Delta missing, server failed to create it: Delta was not created since new package is too small: Delta-upgrade statistics: Deltas: %(present)d present and %(absent)d not, Downloaded head of %s. Downloaded, time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s Downloading head of %s... Error: --gpg-home `%s' does not exist. Error: `%s' does not seem to be a Debian delta. Error: `%s' does not seem to be a Debian package. Error: `%s' is not a regular file. Error: argument is not a directory or a regular file: Error: argument of --alt is not a directory or a regular file: Error: argument of --dir is not a directory: Error: argument of --forensicdir is not a directory: Error: argument of --old is not a directory or a regular file: Error: feature `%s' cannot be disabled. Error: option `%s' is unknown, try --help Error: output format `%s' is unknown. Error: testing of delta failed: Error: the file `%s' does not exist. Failed! Safe upgrading APT cache... Faulty delta. Please send by email to %s the following files:
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
 Usage: debdelta-upgrade [package names]
  Downloads all deltas and apply them to create the debs
  that are needed by 'apt-get upgrade'.

Options:
--dir DIR   directory where to save results
--deb-policy POLICY
            policy to decide which debs to download,
 -A         accept unsigned deltas
--format FORMAT
            format of created debs
--timeout SECONDS
            adjust timeout for connections, default is
            15 seconds
 Usage: debdeltas [ option...  ]  [deb files and dirs, or 'Packages' files]
  Computes all missing deltas for deb files.
  It orders by version number and produce deltas to the newest version

Options:
--signing-key KEY
            key used to sign the deltas (using GnuPG)
--dir DIR   force saving of deltas in this DIR
            (otherwise they go in the dir of the newer deb_file)
--old ARGS  'Packages' files containing list of old versions of debs
--alt ARGS  for any cmdline argument, search for debs also in this place
 -n N       how many deltas to produce for each deb (default unlimited)
--no-md5    do not include MD5 info in delta
--needsold  create a delta that can only be used if the old .deb is available
--delta-algo ALGO
            use a specific backend for computing binary diffs;
            possible values are: xdelta xdelta-bzip xdelta3 bsdiff
 -M Mb      maximum memory to use (for 'bsdiff' or 'xdelta')
--clean-deltas     delete deltas if newer deb is not in archive
--cache     cache parsed version of Packages.bz2 as Packages.debdelta_cache
 Usage: debpatch [ option...  ] delta  fromfile  tofile 
  Applies delta to fromfile and produces a reconstructed  version of tofile.

(When using 'debpatch' and the old .deb is not available,
  use the unpack directory, usually '/', for the fromfile.)

Usage: debpatch --info delta
  Write info on delta.

Options:
--no-md5   do not verify MD5 (if found in info in delta)
 -A        accept unsigned deltas
--format FORMAT
           format of created deb
 Usage: debpatch-url [package names]
  Show URL wherefrom to downloads all deltas that may be used to upgrade the given package names
 WARNING, delta is not signed: Warning, no --old arguments, debdeltas will not generate any deltas. Warning, no non-option arguments, debdeltas does nothing. You may want to examine: You may wish to rerun, to get also: delta is %(perc)3.1f%% of deb; that is, %(save)dkB are saved, on a total of %(tot)dkB. delta time %(time).2f sec, speed %(speed)dkB /sec, (%(algo)s time %(algotime).2fsec speed %(algospeed)dkB /sec) (corr %(corrtime).2f sec) done. downloaded debs,  downloaded deltas,  downloaded so far: time %(time).2fsec, size %(size)s, speed %(speed)4s/sec. failed! trying safe-upgrade... not enough disk space (%(free)dkB) in directory %(dir)s for applying delta (needs %(size)dkB) patching to debs,  size %(size)s time %(time)dsec speed %(speed)s/sec total resulting debs, size %(size)s time %(time)dsec virtual speed %(speed)s/sec upgrading... Project-Id-Version: debdelta
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2017-01-07 18:04+0100
PO-Revision-Date: 2017-01-07 18:05+0100
Last-Translator: A Mennucc <mennucc1@debian.org>
Language-Team: italian <debian-italian@lists.debian.org>
Language: it
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
   Rediretto a:  -v         prolisso (si può usare più volte)
--no-act    non far nulla (far finta di lavorare)
 -d         aggiungi controlli di debug extra
 -k         tiene i file temporanei (per debug)
--gpg-home HOME
            specifica una diversa directory HOME per GPG

Si veda la pagina di manuale per ulteriori opzioni e dettagli.
 Un proxy è definito nell'ambiente; verrà usato "urllib2" per
scaricare; ma questo disabilita alcune caratteristiche e sarà
più lento e malfunzionante. Vedere la pagina di manuale. (Questo delta è difettoso. Potreste riprovare con l'opzione "--forensic=http"). (premere un qualunque tasto) (prelink %(time).2fsec, %(size)dk, %(speed)dk/s) (script %(time).2fsec %(speed)dk/sec) (il 'sources.conf' non specifica un server per '%s') (altro %.2fsec) Creato,    tempo %(time)5.2fsec, velocità %(speed)4s/sec, %(name)s Creazione di: La creazione del delta è fallita: Il delta non è presente: Il delta non è firmato: Il delta è troppo grande: Il delta è assente perché il server non è riuscito a crearlo: Il delta non è stato creato perché il pacchetto nuovo è troppo piccolo: Statistiche di debdelta-upgrade: Delta: %(present)d presenti e %(absent)d non presenti, Scaricato l'inizio di %s. Scaricato, tempo %(time)5.2fsec, velocità %(speed)4s/sec, %(name)s Scaricamento dell'inizio di %s... Errore: --gpg-home '%s' non esiste. Errore: '%s' non sembra essere un delta Debian. Errore: '%s' non sembra essere un pacchetto Debian. Errore: '%s' non è un file regolare. Errore: l'argomento non è una directory o un file regolare: Errore: l'argomento di --alt non è una directory o un file regolare: Errore: l'argomento di --dir non è una directory: Errore: l'argomento di --forensicdir non è una directory: Errore: l'argomento di --old non è una directory o un file regolare: Errore: la caratteristica '%s' non può essere disabilitata. Errore: l'opzione '%s' è sconosciuta, vedere --help Errore: il formato di uscita '%s' è sconosciuto. Errore: il test del delta è fallito: Errore: il file '%s' non esiste. Fallito! Aggiornamento sicuro della cache di APT... Questo delta è difettoso. Si prega di inviare per e-mail a %s i
seguenti file:
 Inizializzazione della cache di APT... Cerco %s Sono necessari tre nomi di file; si veda --help. È necessario un nome di file; si veda --help. Bisogna ancora scaricare %s di delta. Non c'è abbastanza spazio nel disco per salvare '%s'. Non vi è abbastanza spazio disco per scaricare: Ora verrà avviato il programma di invio posta elettronica per mandare
i registri. Creato il deb, tempo: %(time).2fsec, velocità: %(speed)dk/sec I pacchetti deb ricreati saranno salvati nella directory %s Sto mandando i registri al server. Il server risponde: Non è possibile trovare un URI per scaricare il pacchetto
Debian di '%s'. Non è disponibile alcuna sorgente per l'aggiornamento di '%s'. Il pacchetto '%s' è già alla versione più recente. Alcuni delta erano difettosi. Tempo totale: %.1f La cache di APT è stata aggiornata. Aggiornamento della cache di APT... Uso: debdelta [ opzioni...  ] DAFILE AFILE DELTA
  Calcola la differenza fra due deb, da DAFILE a AFILE, e la scrive in DELTA

Opzione:
--signing-key KEY
            chiave usata per firmare il delta (usando GnuPG)
--no-md5    non includere informazione MD5 nel delta
--needsold  crea un delta che può essere usato solo se il
            vecchio deb è disponibile
 -M Mb      memoria massima da usare (per "bsdiff" o "delta")
--delta-algo ALGO
            usa uno specifico backend per calcolare i diff binari
 Uso: debdelta-upgrade [nomi pacchetti]
  Scarica i delta e li applica per creare i deb che servono
  per un 'apt-get upgrade'

Opzioni:
--dir DIR   directory in cui salvare i pacchetti
--deb-policy POLITICA
            politica per accettare quali pacchetti scaricare
 -A         accetta delta non firmati
--format FORMATO
           formato del deb ricostruito
--timeout SECONDS  timeout per le connessione di rete,
          il default è di 15 secondi
 Uso: debdeltas [ opzioni...  ]  [deb e directory, o file "Packages"]
   Calcola i delta per i pacchetti Debian.
   Li ordina per versione e produce i delta verso la versione più nuova.

Opzioni:
--signing-key CHIAVE
            chiave GnuPG usata per firmare i delta
--dir DIR   forza il salvataggio dei delta in DIR
            (altrimenti vanno nella directory del 'deb' più nuovo)
--old ARG   file 'Packages' che contengono le liste delle versioni
            vecchie dei deb
--alt ARG   per ogni argomento nella riga di comando,
            cerca anche in queste directory
 -n N       quanti delta creare per ogni deb (valore predefinito illimitato)
--no-md5    non includere informazioni MD5 nel delta
--needsold  crea un delta che può essere usato solo se il vecchio
            deb è disponibile
--delta-algo ALGO
            usa il backend ALGO per calcolare le differenze binarie;
            valori possibili sono: xdelta xdelta-bzip xdelta3 bsdiff
 -M Mb      massima memoria da usare (per "bsdiff" o "xdelta")
--clean-deltas
            elimina i delta se il deb più nuovo non è presente in archivio
--cache     tiene una cache dei Packages.bz2 in Packages.debdelta_cache
 Uso: debpatch [ opzioni...  ] DELTA DAFILE AFILE 
  Applica DELTA a DAFILE e produce una versione ricostruita di AFILE.

(Se il vecchio deb non è disponibile, ma avete lo avete spacchettato
in una directory, allora potete indicare la directory come DAFILE;
in particolare se avete installato il vecchio deb, allora usate "/" come DAFILE)

Uso: debpatch --info DELTA
  Scrive informazioni sul DELTA.

Opzioni:
--no-md5   non verifica lo MD5 (se è presente nelle informazione in delta)
 -A        accetta delta non firmati
--format FORMATO
           formato del deb ricostruito
 Uso: debpatch-url [nomi pacchetti]
  Mostra lo URL da cui scaricare i delta che possono aggiornare i
  pacchetti indicati.
 ATTENZIONE: il delta non è firmato: Attenzione, manca l'opzione --old, debdeltas non genererà alcun delta. Attenzione, non ci sono argomenti non-opzioni, debdeltas non fa nulla. Potresti voler esaminare: Si può riprovare più tardi per scaricare anche: il delta è %(perc)3.1f%% del deb; cioè, sono stati risparmiati %(save)dkB su un totale di %(tot)dkB. delta tempo %(time).2f sec, velocità %(speed)dkB /sec, (%(algo)s tempo %(algotime).2fsec velocità %(algospeed)dkB /sec) (corr %(corrtime).2f sec) fatto. deb scaricati,  delta scaricati,  scaricato finora: tempo %(time).2fsec, dimensione %(size)s, velocità %(speed)4s/sec. fallito! provo l'aggiornamento sicuro... non c'è abbastanza spazio su disco (%(free)dkB) nella directory
%(dir)s per applicare il delta (servono %(size)dkB) deb creati,  dimensione %(size)s tempo %(time)dsec velocità %(speed)s/sec totale deb risultanti, dimensione %(size)s tempo %(time)dsec velocità virtuale %(speed)s/sec aggiornamento... 