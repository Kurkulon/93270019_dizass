#include <idc.idc>

static main()
{
	auto start;
	auto end;
	auto asmstr;
	auto op1, op2;
	auto optp1, optp2;
	auto xrefTo;
	auto refType;
	auto baseReg;
	auto xrefCount;
	
	
	start = GetFunctionAttr(ScreenEA(), FUNCATTR_START);
	
	if (start == -1)
	{
		return;
	};

	xrefCount = ProcessFuncXref(start);

//	Message("Finished processing %u xrefs.\n", xrefCount);
}

static ProcessFuncXref(start)
{
//	auto start;
	auto end;
	auto asmstr;
	auto op1, op2;
	auto optp1, optp2;
	auto xrefTo;
	auto refType;
	auto baseReg;
	auto xrefCount;
	
	
//	start = GetFunctionAttr(ScreenEA(), FUNCATTR_START);
	
	end = GetFunctionAttr(start, FUNCATTR_END);

	if (start == -1 || end == -1)
	{
		return 0;
	};

	xrefCount = 0;

	Message("\nStarting find data xref from function %s\n", GetFunctionName(start));

	while (start <= end)
	{
		asmstr = GetDisasm(start);
	
		if (asmstr[:5] == "mov.l")
		{
			optp1 = GetOpType(start, 0);
			optp2 = GetOpType(start, 1);
			
			if (optp1 == 5 && optp2 == 1) // optp1 == Immediate, optp2 == Register
			{
//				Message("%08X  %s\n", start, asmstr);

				xrefTo = GetOperandValue(start, 0);
				baseReg = GetOperandValue(start, 1);
				
				start = start + 2;

				if (start > end) break;

				asmstr = GetDisasm(start);

				if (asmstr[:4] == "mov.")
				{
					optp1 = GetOpType(start, 0);
					optp2 = GetOpType(start, 1);
					op1 = GetOperandValue(start, 0);
					op2 = GetOperandValue(start, 1);
					
					if (optp1 == 3 && optp2 == 1 && op1 == baseReg) // mov.w   @r10, r0 ;optp1 == Base + Index, optp2 == Register
					{
//						Message("%08X  %s\n", start, asmstr);

						add_dref(start, xrefTo, dr_R | XREF_USER); 
						start = start + 2;
						xrefCount = xrefCount + 1;
					}
					else if (optp1 == 1 && optp2 == 3 && op2 == baseReg) // mov.w   r0, @r10 ;optp1 == Register, optp2 == Base + Index
					{
//						Message("%08X  %s\n", start, asmstr);

						add_dref(start, xrefTo, dr_W | XREF_USER); 
						start = start + 2;
						xrefCount = xrefCount + 1;
					};
				}
				else if (asmstr[:3] == "jsr")
				{
//					Message("%08X  %s\n", start, asmstr);

					optp1 = GetOpType(start, 0);
					op1 = GetOperandValue(start, 0);

					if (optp1 == 3 && op1 == baseReg)
					{
						xrefCount = xrefCount + ProcessFuncXref(xrefTo);
						start = start + 2;
					};
				}
				else
				{
					start = start + 2;
				};
			}
			else
			{
				start = start + 2;
			};
		}
		else if (asmstr[:3] == "bsr")
		{
//			Message("%08X  %s\n", start, asmstr);

			optp1 = GetOpType(start, 0);
			op1 = Eval(GetOpnd(start, 0));

			if (optp1 == 7)
			{
				xrefCount = xrefCount + ProcessFuncXref(op1);
				start = start + 2;
			};
		}
		else
		{
			start = start + 2;
		};
	};
	
	Message("Finished processing %u xrefs.\n", xrefCount);
	
	return xrefCount;
}

