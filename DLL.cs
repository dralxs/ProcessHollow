using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using DInvoke.DynamicInvoke;

namespace ProcessHollow
{
    internal class DLL
    {
        public string name;

        public object ChaseFunction(string fname)
        {
            var type = (from assembly in AppDomain.CurrentDomain.GetAssemblies()
                        from t in assembly.GetTypes()
                        where t.Name == fname
                        select t).FirstOrDefault();
            this.CheckNull(type, fname + " not found");
            var p = Generic.GetLibraryAddress(this.name, fname, true);
            this.CheckNullPtr(p, fname);
            var x = Marshal.GetDelegateForFunctionPointer(p, type);
            this.CheckNull(x, "GetDelegateForFunctionPointer");
            return x;
        }

        public DLL(string name)
        {
            this.name = name;
        }

        public void CheckNull(object test, string label)
        {
            if (test == null)
            {
                Console.WriteLine("Error: {0} is null", label);
                Environment.Exit(1);
            }
        }

        public void CheckNullPtr(IntPtr test, string label)
        {
            if (test == IntPtr.Zero)
            {
                Console.WriteLine("Error: {0} is INtPtr.Zero", label);
                Environment.Exit(1);
            }
        }
    }
}
