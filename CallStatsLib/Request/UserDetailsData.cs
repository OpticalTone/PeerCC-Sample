﻿namespace CallStatsLib.Request
{
    public class UserDetailsData
    {
        public string localID { get; set; }
        public string originID { get; set; }
        public string deviceID { get; set; }
        public long timestamp { get; set; }
        public string userName { get; set; }
    }
}
