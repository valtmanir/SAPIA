using System;
using System.IO;
using NuGetPackageExplorer.Types;

namespace API_Security_Unit_Test 
{
    // TODO: replace '.extension' with your custom extension
    [PackageContentViewerMetadata(0, ".extension", ".anotherextension")]
    internal class MyCustomContentViewer : IPackageContentViewer 
    {
        public object GetView(string extension, Stream stream) 
        {
            throw new NotImplementedException();
        }
    }
}