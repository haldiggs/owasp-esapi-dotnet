using System;
using System.Web;

namespace HttpInterfaces
{
    public interface ITraceContext
    {
        TraceMode TraceMode { get; set; }
        
        bool IsEnabled { get; set; }
        
        event TraceContextEventHandler TraceFinished;
        
        void Write(string message);
        
        void Write(string category, string message);
        
        void Write(string category, string message, Exception errorInfo);
        
        void Warn(string message);
        
        void Warn(string category, string message);
        
        void Warn(string category, string message, Exception errorInfo);
    }
}
