using System;
using System.IO;

namespace HttpInterfaces
{
    public interface IHttpPostedFile
    {
        int ContentLength { get; }

        string ContentType { get; }

        string FileName { get; }

        Stream InputStream { get; }

        void SaveAs(string FileName);
    }
}
