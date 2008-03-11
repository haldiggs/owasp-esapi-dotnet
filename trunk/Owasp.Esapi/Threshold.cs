/// <summary> OWASP Enterprise Security API .NET (ESAPI.NET)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2008 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Alex Smolen <a href="http://www.foundstone.com">Foundstone</a>
/// </author>
/// <created>  2008 </created>

using System;
using System.Collections;

namespace Owasp.Esapi
{
    /// <summary>
    /// Used by the intrusion detector, this class represent a switch which tracks the number of occurences 
    /// of a certain type of exception per user and performs a corresponding action.
    /// </summary>
    public class Threshold
    {
        /// <summary>
        /// The name of the event.
        /// </summary>
		public string Name = null;

        /// <summary>
        /// The number of occurences.
        /// </summary>
		public int Count = 0;
        
        /// <summary>
        /// The interval allowed between events.
        /// </summary>
		public long Interval = 0;
        
        /// <summary>
        /// The list of actions associated with the threshold/
        /// </summary>
		public IList Actions = null;
		
		/// <summary>
		/// Constructor for Threshold
		/// </summary>
		/// <param name="name">
        /// Event name.
        /// </param>
		/// <param name="count">
        /// Count of events allowed.
        /// </param>
		/// <param name="interval">
        /// Interval between events allowed.
        /// </param>
		/// <param name="actions">
        /// Actions associated with threshold.
        /// </param>
        public Threshold(string name, int count, long interval, IList actions)
		{
			this.Name = name;
			this.Count = count;
			this.Interval = interval;
			this.Actions = actions;
		}
		
        /// <summary>
        /// Returns string representation of threshold.
        /// </summary>
        /// <returns>String representation of threshold.</returns>
		public override string ToString()
		{
			return "Threshold: " + Name + " - " + Count + " in " + Interval + " seconds results in " + Actions.ToString();
		}
	}
}