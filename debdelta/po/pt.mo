��    M      �  g   �      �  $  �  �   �  L   R     �  0   �  %   �  1   	     6	  ?   L	  	   �	  !   �	     �	     �	     �	     �	  /   
     ?
  ?   V
     �
  &   �
  /   �
  1     "   9  5   \  >   �  ,   �  4   �  >   3  '   r  )   �  %   �     �  $   
  #   /  >   S     �  	   �     �     �     �  '     "   3  .   V  7   �  ,   �     �       A     .   T  9   �     �     �     �       �    �  �  /  �  �  �  �   �     ;  D   Y  9   �     �  #   �  V     �   l     �     �       K   "     n  ]   �     �  2   �  P   1     �  �  �  U  0  �   �   Y   >!     �!  2   �!  %   �!  1   "     @"  D   W"     �"  $   �"     �"     �"      #  )   #  :   E#     �#  G   �#     �#  "   $  +   &$  ,   R$  '   $  ?   �$  H   �$  0   0%  7   a%  H   �%  6   �%  2   &  -   L&     z&  "   �&  9   �&  M   �&     E'     e'  .   q'  -   �'     �'  9   �'  6   '(  @   ^(  K   �(  2   �(  %   )     D)  Q   Z)  <   �)  >   �)     (*     F*     f*     �*    �*  �  �,  �  �.  #  �3  �   �5  !   j6  J   �6  @   �6     7  9   .7  Y   h7  �   �7     [8     b8     w8  Z   �8  *   �8  u   9     �9  ;   �9  ^   �9     B:     0              !   +   8       L   =   :          F          $      9         M   '       #         &       1           ,       -   >   (         	           %         7       3          /       "   @      .           K   D   <   H              )   B      
   C   G          2                    6   ;                    5      E          4      *      ?          A   I       J     -v         verbose (can be added multiple times)
--no-act    do not do that (whatever it is!)
 -d         add extra debugging checks
 -k         keep temporary files (use for debugging)
--gpg-home HOME
            specify a different home for GPG

See man page for more options and details.
  Proxy settings detected in the environment; using "urllib2" for downloading; but
  this disables some features and is in general slower and buggier. See man page. (Faulty delta. Please consider retrying with the option "--forensic=http" ). (hit any key) (prelink %(time).2fsec, %(size)dk, %(speed)dk/s) (script %(time).2fsec %(speed)dk/sec) (sources.conf does not provide a server for `%s') (unaccounted %.2fsec) Created,    time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s Creating: Creation of delta failed, reason: Delta is not present: Delta is not signed: Delta is too big: Delta-upgrade statistics: Deltas: %(present)d present and %(absent)d not, Downloaded head of %s. Downloaded, time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s Downloading head of %s... Error: --gpg-home `%s' does not exist. Error: `%s' does not seem to be a Debian delta. Error: `%s' does not seem to be a Debian package. Error: `%s' is not a regular file. Error: argument is not a directory or a regular file: Error: argument of --alt is not a directory or a regular file: Error: argument of --dir is not a directory: Error: argument of --forensicdir is not a directory: Error: argument of --old is not a directory or a regular file: Error: feature `%s' cannot be disabled. Error: option `%s' is unknown, try --help Error: output format `%s' is unknown. Error: testing of delta failed: Error: the file `%s' does not exist. Failed! Safe upgrading APT cache... Faulty delta. Please send by email to %s the following files:
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
 WARNING, delta is not signed: Warning, no --old arguments, debdeltas will not generate any deltas. Warning, no non-option arguments, debdeltas does nothing. You may want to examine: You may wish to rerun, to get also: delta is %(perc)3.1f%% of deb; that is, %(save)dkB are saved, on a total of %(tot)dkB. delta time %(time).2f sec, speed %(speed)dkB /sec, (%(algo)s time %(algotime).2fsec speed %(algospeed)dkB /sec) (corr %(corrtime).2f sec) done. downloaded debs,  downloaded deltas,  downloaded so far: time %(time).2fsec, size %(size)s, speed %(speed)4s/sec. failed! trying safe-upgrade... not enough disk space (%(free)dkB) in directory %(dir)s for applying delta (needs %(size)dkB) patching to debs,  size %(size)s time %(time)dsec speed %(speed)s/sec total resulting debs, size %(size)s time %(time)dsec virtual speed %(speed)s/sec upgrading... Project-Id-Version: debdelta 0.50+2
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2017-01-03 22:12+0100
PO-Revision-Date: 2017-01-21 15:23+0000
Last-Translator: Miguel Figueiredo <elmig@debianpt.org>
Language-Team: Portuguese <traduz@debianpt.org>
Language: pt
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Lokalize 1.4
  -v         detalhado (pode ser adiciona várias vezes)
--no-act    não faz isso (seja o que for!)
 -d         adiciona verificações extra de depuração
 -k         mantêm os ficheiros temporários (usado para depuração)
--gpg-home HOME
            especifica uma home diferente para GPG

Veja o manual para mais opções e detalhes.
  Detectadas configurações de Proxy no ambiente; a usar "urllib2" para descarga, mas
  isto desactiva algumas funcionalidades e é em geral mais lento e problemático. Veja o manual. (Delta com defeito. Por favor considere tentar de novo com o opção "--forensic=http" ). (carregue em qualquer tecla) (pré-link %(time).2fsec, %(size)dk, %(speed)dk/s) (script %(time).2fsec %(speed)dk/sec) (sources.conf não fornece um servidor para `%s') (não contado %.2fsec) Criado,    tempo %(time)5.2fsec, velocidade %(speed)4s/sec, %(name)s A criar: Falhou a criação do delta, razão: Delta não está presente: Delta não está assinado: Delta é demasiado grande: Estatísticas de actualização de delta: Deltas: %(present)d presentes e %(absent)d não presentes, Descarregada cabeça de %s. Descarregado, tempo %(time)5.2fsec, velocidade %(speed)4s/sec, %(name)s A descarregar cabeça de %s... Erro: --gpg-home `%s' não existe. Erro: `%s' não parece ser um delta Debian. Erro: `%s' não parece ser um pacote Debian. Erro: `%s' não é um ficheiro regular. Erro: argumento não é um directório nem um ficheiro regular: Erro: argumento de --alt não é um directório nem um ficheiro regular: Erro: argumento de --dir não é um directório: Erro: argumento de -forensicdir não é um directório: Erro: argumento de --old não é um directório nem um ficheiro regular: Erro: a funcionalidade `%s' não pode ser desactivada. Erro: a opção `%s' é desconhecida, tente --help Erro: formato de saída `%s' é desconhecido. Erro: testes do delta falhados: Erro: o ficheiro `%s' não existe. Falhado! A fazer actualização segura da cache de APT... Delta com defeito. Por favor envie os seguintes ficheiros por email para %s:
 a inicializar a cache do APT... Procurar %s Preciso de 3 nomes de ficheiros; tente --help. Preciso de um nome de ficheiro; tente --help. Preciso de obter %s de deltas. Não há espaço de disco suficiente para armazenar `%s'. Não há espaço de disco suficiente para descarregar. Agora a invocar o transporte de mail para enviar os relatórios. Aplicação de patch pronta, tempo %(time).2fsec, velocidade %(speed)dk/sec Os debs recriados são guardados no directório %s A enviar relatórios para o servidor. Resposta do servidor: Desculpe, não consigo encontrar um URL para descarregar o pacote debian de `%s'. Desculpe, não há fontes disponíveis para actualizar `%s'. Desculpe, o pacote `%s' já está na sua versão mais recente. Existiram deltas com defeito. Tempo total de execução: %.1f Cache de APT actualizada. a actualizar a cache do APT... Utilização: debdelta [ opção...  ] fromfile tofile delta
  Computa a diferença de dois ficheiros deb, de fromfile para tofile, e escreve-a no delta

Opções:
--signing-key CHAVE
            chave gnupg usada para assinar o delta
--no-md5    não inclui informação MD5 no delta
--needsold  cria um delta que só pode ser usado se o deb antigo estiver disponível -M Mb      máximo de memória a usar (para 'bsdiff' ou 'xdelta')
--delta-algo ALGO
            usa um backend específico para computar diferenças de binários
 Utilização: debdelta-upgrade [nomes de pacotes]
  Descarrega todos os deltas e aplica-os para criar os debs que são
  necessários pelo 'apt-get upgrade'.

Opções:
--dir DIR  directório onde guardar os resultados
--deb-policy POLITICA
           politica para decidir quais debs descarregar,
 -A        aceita deltas não assinados
--format FORMATO
           formato dos debs criados
--timeout SEGUNDOS
           ajusta o timeout das ligações, o predefinido é
           15 segundos
 Utilização: debdeltas [ opção...  ]  [ficheiros deb e directórios, ou ficheiros 'Packages']
  Computa todos os deltas em falta para ficheiros deb.
  Organiza por número de versão e produz deltas para a versão mais recente

Opções:
--signing-key CHAVE
            chave usada para assinar os deltas (usando GnuPG)
--dir DIR   força a gravação dos deltas neste DIRECTÓRIO
            (de outro modo eles irão para o directório do ficheiro deb mais recente)
--old ARGUMENTOS  ficheiros 'Packages' que contêm uma lista de versões antigas de debs
--alt ARGUMENTOS  para qualquer argumento de linha de comandos, procure também por debs aqui
 -n N       quantos deltas produzir para cada deb (predefinição ilimitado)
--no-md5    não inclui informação MD5 no delta
--needsold  cria um delta que apenas pode ser usado se o antigo .deb estiver disponível
--delta-algo ALGO
            usa um backend específico para computar diferenças de binários;
            os valores possíveis são: xdelta xdelta-bzip xdelta3 bsdiff
 -M Mb      máximo de memória a usar (para 'bsdiff' ou 'xdelta')
--clean-deltas     apaga os deltas se o deb mais recente não estiver no arquivo
--cache    cache da versão interpretada de Packages.bz2 como Packages.debdelta_cache
 Utilização: debpatch [ opção...  ] delta  de-ficheiro  para-ficheiro 
  Aplica o delta ao de-ficheiro e produz uma versão reconstruída de para-ficheiro.

(Quando se usa 'debpatch' e o .deb antigo não está disponível,
  use o directório para desempacotar, geralmente '/' para o de-ficheiro.)

Utilização: debpatch --info delta
  Escreve informação no delta.

Opções:
--no-md5   não verificar o MD5 (se encontrado em informações no delta)
 -A        aceitar deltas não assinados
--format FORMATO
           formato do deb criado
 Utilização: debpatch-url [nomes de pacotes]
  Mostra o URL de onde descarregar todos os deltas que possam ser usados para actualizar os nomes de pacotes fornecidos
 AVISO, delta não está assinado: Aviso, nenhum argumento --old, o debdeltas não irá gerar nenhuns deltas. Aviso, nenhum argumento não-opção, o debdeltas não faz nada. Pode querer examinar: Você pode desejar voltar a executar, para também obter: delta é %(perc)3.1f%% de deb; isto é, %(save)dkB são salvados, num total de %(tot)dkB. tempo de delta %(time).2f sec, velocidade %(speed)dkB /sec, (%(algo)s tempo %(algotime).2fsec velocidade %(algospeed)dkB /sec) (corr %(corrtime).2f sec) feito. debs descarregados,  deltas descarregados,  descarregado até agora: tempo %(time).2fsec, tamanho %(size)s, velocidade %(speed)4s/sec. falhado! a tentar actualização segura... não há espaço de disco suficiente (%(free)dkB) no directório %(dir)s para aplicar o delta (precisa de %(size)dkB) a aplicar patches aos debs,  tamanho %(size)s tempo %(time)dsec velocidade %(speed)s/sec total de debs resultantes, tamanho %(size)s tempo %(time)dsec velocidade virtual %(speed)s/sec a actualizar... 