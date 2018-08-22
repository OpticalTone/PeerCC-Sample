using CallStatsLib;
using CallStatsLib.Request;
using Jose;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Connectivity;

namespace PeerConnectionClient
{
    public class CallStatsClient
    {
        private static string _localID = GetLocalPeerName();
        private static string _appID = (string)Config.localSettings.Values["appID"];
        private static string _keyID = (string)Config.localSettings.Values["keyID"];
        private static readonly string _jti = new Func<string>(() =>
        {
            Random random = new Random();
            const string chars = "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const int length = 10;
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        })();

        private static string _confID = Config.localSettings.Values["confID"].ToString();

        private static string _originID = "PeerCC";
        private static string _deviceID = "desktop";
        private static string _connectionID = "SampleConnection";
        private static string _remoteID = "RemotePeer";

        private static string GenerateJWT()
        {
            var header = new Dictionary<string, object>()
            {
                { "typ", "JWT" },
                { "alg", "ES256" }
            };

            var payload = new Dictionary<string, object>()
            {
                { "userID", _localID},
                { "appID", _appID},
                { "keyID", _keyID },
                { "iat", DateTime.UtcNow.ToUnixTimeStampSeconds() },
                { "nbf", DateTime.UtcNow.AddMinutes(-5).ToUnixTimeStampSeconds() },
                { "exp", DateTime.UtcNow.AddHours(1).ToUnixTimeStampSeconds() },
                { "jti", _jti }
            };

            try
            {
                string eccKey = @"ecc-key.p12";
                if (File.Exists(eccKey))
                {
                    if (new FileInfo(eccKey).Length != 0)
                    {
                        return JWT.Encode(payload, new X509Certificate2(eccKey,
                            (string)Config.localSettings.Values["secret"]).GetECDsaPrivateKey(),
                            JwsAlgorithm.ES256, extraHeaders: header);
                    }
                    else
                    {
                        Debug.WriteLine("[Error] File is empty.");
                        return string.Empty;
                    }
                }
                else
                {
                    Debug.WriteLine("[Error] File does not exist.");
                    return string.Empty;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Error] GenerateJWT: {ex.Message}");
                return string.Empty;
            }
        }

        private CallStats callstats = new CallStats(_localID, _appID, _keyID, _confID, GenerateJWT());
        private FabricSetupData fabricSetupData = new FabricSetupData();
        private enum FabricTransmissionDirection { sendrecv, sendonly, receiveonly }
        private enum RemoteEndpointType { peer, server }
        private enum IceCandidateState { frozen, waiting, inprogress, failed, succeeded, cancelled }

        private SSRCMapData ssrcMapData = new SSRCMapData();
        private static List<SSRCData> ssrcDataList = new List<SSRCData>();

        public async Task InitializeCallStats()
        {
            fabricSetupData.localID = _localID;
            fabricSetupData.originID = _originID;
            fabricSetupData.deviceID = _deviceID;
            fabricSetupData.timestamp = DateTime.UtcNow.ToUnixTimeStampMiliseconds();
            fabricSetupData.connectionID = _connectionID;
            fabricSetupData.remoteID = _remoteID;
            fabricSetupData.delay = 5;
            fabricSetupData.iceGatheringDelay = 3;
            fabricSetupData.iceConnectivityDelay = 2;
            fabricSetupData.fabricTransmissionDirection = FabricTransmissionDirection.sendrecv.ToString();
            fabricSetupData.remoteEndpointType = RemoteEndpointType.peer.ToString();
            fabricSetupData.localIceCandidates = localIceCandidatesList;
            fabricSetupData.remoteIceCandidates = remoteIceCandidatesList;
            fabricSetupData.iceCandidatePairs = iceCandidatePairsList;

            ssrcMapData.localID = _localID;
            ssrcMapData.originID = _originID;
            ssrcMapData.deviceID = _deviceID;
            ssrcMapData.timestamp = DateTime.UtcNow.ToUnixTimeStampMiliseconds();
            ssrcMapData.connectionID = _connectionID;
            ssrcMapData.remoteID = _remoteID;
            ssrcMapData.ssrcData = ssrcDataList;

            await callstats.StepsToIntegrate(
                CreateConference(),
                UserAlive(),
                fabricSetupData,  
                FabricSetupFailed(), 
                ssrcMapData, null, null, null
                //conferenceStatsSubmissionData,
                //FabricTerminated(),
                //UserLeft()
                );
        }

        private enum StreamType { inbound, outbound }
        private enum ReportType { local, remote }
        private enum MediaType { audio, video, screen }

        public static void SSRCMapDataSetup(string sdp)
        {
            var dict = ParseSdp(sdp, "a=ssrc:");

            foreach (var d in dict)
            {
                Debug.WriteLine($"!!!key1: {d.Key}, value1: {d.Value}");

                SSRCData ssrcData = new SSRCData();

                ssrcData.ssrc = d.Key;

                foreach (var k in d.Value)
                {
                    Debug.WriteLine($"!!!key2: {k.Key}, value2: {k.Value}");

                    if (k.Key == "cname") ssrcData.cname = k.Value;
                    if (k.Key == "msid") ssrcData.msid = k.Value;
                    if (k.Key == "mslabel") ssrcData.mslabel = k.Value;
                    if (k.Key == "label") ssrcData.label = k.Value;
                }

                ssrcData.streamType = StreamType.inbound.ToString();
                ssrcData.reportType = ReportType.local.ToString();
                ssrcData.mediaType = MediaType.audio.ToString();
                ssrcData.userID = GetLocalPeerName();

                ssrcData.localStartTime = DateTime.UtcNow.ToUnixTimeStampMiliseconds();

                ssrcDataList.Add(ssrcData);
            }
        }

        private static Dictionary<string, Dictionary<string, string>> ParseSdp(string sdp, string searchFirstStr)
        {
            var dict = new Dictionary<string, Dictionary<string, string>>();

            List<string> listSdpLines = sdp.Split('\n').ToList();
            List<string> listFirstStr = new List<string>();

            string firstId = string.Empty;

            string searchFirstId = searchFirstStr + firstId;

            for (int i = 0; i < listSdpLines.Count; i++)
            {
                if (listSdpLines[i].StartsWith(searchFirstStr))
                    listFirstStr.Add(listSdpLines[i]);
            }

            for (int i = 0; i < listFirstStr.Count; i++)
            {
                int statrtIndex = listFirstStr[i].IndexOf(":") + 1;
                int endIndex = listFirstStr[i].IndexOf(" ");

                string id = listFirstStr[i].Substring(statrtIndex, endIndex - statrtIndex);

                if (id != firstId)
                {
                    firstId = id;
                    dict.Add(firstId, new Dictionary<string, string>());
                }

                int start = searchFirstId.Length + 1;

                string sub = listFirstStr[i].Substring(start);

                int startValue = sub.IndexOf(":");
                int startProperty = sub.IndexOf(" ") + 1;

                string property = sub.Substring(startProperty, startValue - startProperty);
                string value = sub.Substring(startValue + 1);

                dict[firstId].Add(property, value);
            }
            return dict;
        }

        private enum EndpointInfoType { browser, native, plugin, middlebox }

        private CreateConferenceData CreateConference()
        {
            EndpointInfo endpointInfo = new EndpointInfo();
            endpointInfo.type = EndpointInfoType.native.ToString();
            endpointInfo.os = Environment.OSVersion.ToString();
            endpointInfo.buildName = "SampleBuild";
            endpointInfo.buildVersion = "sb01";
            endpointInfo.appVersion = "1.0";

            CreateConferenceData data = new CreateConferenceData();
            data.localID = _localID;
            data.originID = "SampleOrigin";
            data.deviceID = GetLocalPeerName();
            data.timestamp = DateTime.UtcNow.ToUnixTimeStampMiliseconds();
            data.endpointInfo = endpointInfo;

            return data;
        }

        private UserAliveData UserAlive()
        {
            UserAliveData data = new UserAliveData();
            data.localID = _localID;
            data.originID = "SampleOrigin";
            data.deviceID = GetLocalPeerName();
            data.timestamp = DateTime.UtcNow.ToUnixTimeStampMiliseconds();

            return data;
        }

        private static List<IceCandidate> localIceCandidatesList = new List<IceCandidate>();
        private static List<IceCandidate> remoteIceCandidatesList = new List<IceCandidate>();
        private static List<IceCandidatePair> iceCandidatePairsList = new List<IceCandidatePair>();

        public static void FabricSetupLocalCandidate(string candidateStr)
        {
            string candidate = candidateStr.Substring(candidateStr.LastIndexOf(':') + 1);

            string[] separatingChars = { " " };
            string[] words = candidate.Split(separatingChars, StringSplitOptions.None);

            var candidateID = words[0];
            var candidateTransport = words[2];
            var localCandidate = words[3];
            var candidateIp = words[4];
            var candidatePort = words[5];
            var candidateType = words[7];

            Debug.WriteLine($"!!!candidateID: {candidateID}, " +
                $"candidateTransport: {candidateTransport}, " +
                $"localCandidate: {localCandidate}, " +
                $"candidateIp: {candidateIp}, " +
                $"candidatePort: {candidatePort}, " +
                $"candidateType: {candidateType}");

            IceCandidate localIceCandidateObj = new IceCandidate();
            localIceCandidateObj.id = localCandidate;
            localIceCandidateObj.type = "localcandidate";
            localIceCandidateObj.ip = candidateIp;
            localIceCandidateObj.port = int.Parse(candidatePort);
            localIceCandidateObj.candidateType = candidateType;
            localIceCandidateObj.transport = candidateTransport;
            localIceCandidatesList.Add(localIceCandidateObj);
        }

        public static void FabricSetupRemoteCandidate(string candidate)
        {
            string[] separatingChars = { " " };
            string[] words = candidate.Split(separatingChars, StringSplitOptions.None);

            string[] candidateStr = words[0].Split(":", StringSplitOptions.None);

            var candidateID = candidateStr[1];
            var candidateTransport = words[2];
            var localCandidateID = words[3];
            var candidateIp = words[4];
            var candidatePort = words[5];
            var candidateType = words[7];

            Debug.WriteLine($"!!!candidateID: {candidateID}, " +
               $"candidateTransport: {candidateTransport}, " +
               $"localCandidateID: {localCandidateID}, " +
               $"candidateIp: {candidateIp}, " +
               $"candidatePort: {candidatePort}, " +
               $"candidateType: {candidateType}");

            IceCandidate remoteIceCandidateObj = new IceCandidate();
            remoteIceCandidateObj.id = candidateID;
            remoteIceCandidateObj.type = "remotecandidate";
            remoteIceCandidateObj.ip = candidateIp;
            remoteIceCandidateObj.port = int.Parse(candidatePort);
            remoteIceCandidateObj.candidateType = candidateType;
            remoteIceCandidateObj.transport = candidateTransport;
            remoteIceCandidatesList.Add(remoteIceCandidateObj);

            IceCandidatePair iceCandidatePairObj = new IceCandidatePair();
            iceCandidatePairObj.id = candidateID;
            iceCandidatePairObj.localCandidateId = localCandidateID;
            iceCandidatePairObj.remoteCandidateId = candidateID;
            iceCandidatePairObj.state = IceCandidateState.succeeded.ToString();
            iceCandidatePairObj.priority = 1;
            iceCandidatePairObj.nominated = true;
            iceCandidatePairsList.Add(iceCandidatePairObj);
        }

        public async Task FabricSetup()
        {
            await Task.Delay(20000);
            Debug.WriteLine("FabricSetup: ");
            var fabricStatus = await callstats.FabricSetup(fabricSetupData);
        }

        private enum FabricSetupFailedReason
        {
            MediaConfigError, MediaPermissionError, MediaDeviceError, NegotiationFailure,
            SDPGenerationError, TransportFailure, SignalingError, IceConnectionFailure
        }

        private FabricSetupFailedData FabricSetupFailed()
        {
            FabricSetupFailedData fabricSetupFailedData = new FabricSetupFailedData();
            fabricSetupFailedData.localID = _localID;
            fabricSetupFailedData.originID = "SampleOrigin";
            fabricSetupFailedData.deviceID = GetLocalPeerName();
            fabricSetupFailedData.timestamp = DateTime.UtcNow.ToUnixTimeStampMiliseconds();
            fabricSetupFailedData.fabricTransmissionDirection = FabricTransmissionDirection.sendrecv.ToString();
            fabricSetupFailedData.remoteEndpointType = RemoteEndpointType.peer.ToString();
            fabricSetupFailedData.reason = FabricSetupFailedReason.SignalingError.ToString();
            fabricSetupFailedData.name = "name";
            fabricSetupFailedData.message = "message";
            fabricSetupFailedData.stack = "stack";

            return fabricSetupFailedData;
        }

        /// <summary>
        /// Constructs and returns the local peer name.
        /// </summary>
        /// <returns>The local peer name.</returns>
        private static string GetLocalPeerName()
        {
            var hostname = NetworkInformation.GetHostNames().FirstOrDefault(h => h.Type == HostNameType.DomainName);
            string ret = hostname?.CanonicalName ?? "<unknown host>";
            return ret;
        }
    }

    public static class DateTimeExtensions
    {
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static long ToUnixTimeStampSeconds(this DateTime dateTimeUtc)
        {
            return (long)Math.Round((dateTimeUtc.ToUniversalTime() - UnixEpoch).TotalSeconds);
        }

        public static long ToUnixTimeStampMiliseconds(this DateTime dateTimeUtc)
        {
            return (long)Math.Round((dateTimeUtc.ToUniversalTime() - UnixEpoch).TotalMilliseconds);
        }
    }
}
