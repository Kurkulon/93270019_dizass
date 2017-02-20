#include <idc.idc>

static main() {
  auto i;
  auto base;
  auto fp;
  auto mName;

  Message("\nStarting MUT processing.\n");

  base = ScreenEA();
  i = 0;

  fp = fopen("MUT_requests.txt", "r");
  if (fp != 0)
  {
	Message("File MUT_requests.txt open.\n");

	while (1)
	{
		mName = readstr(fp);
		if(mName == -1) break;

		if(strstr(mName, "\n") > 0) mName = substr(mName, 0, -2);

		if(mName == "") break; 

		MakeDword(base + i * 4);
		MakeName(Dword(base + i * 4), "b" + mName);

//		MakeWord(Dword(base + i * 4) - 1);
//		MakeName(Dword(base + i * 4) - 1, "w" + mName);

		i++;

	}
	fclose(fp);
  }
  else
	Message("File MUT_requests.txt not open.\n");

  Message("Finished MUT processing.\n");
}

