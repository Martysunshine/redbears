import {afterEach, describe, expect, it, vi} from "vitest";
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
const {start, status, get, lab}=vi.hoisted(()=>({start:vi.fn(),status:vi.fn(),get:vi.fn(),lab:vi.fn()}));
vi.mock("@/lib/api",()=>({startResearch:start,researchStatus:status,getResearch:get,validateResearchLab:lab,cancelResearch:vi.fn()}));
import {ResearchPanel} from "../ResearchPanel";
afterEach(()=>{cleanup();sessionStorage.clear();vi.clearAllMocks()});
const record={id:"abc",question:"q",status:"unavailable",model:"",usage:{searches:0,reads:0},events:[{seq:1,type:"stopped",reason:"Missing configuration: NEBIUS_API_KEY"}],sources:[],report:null};
describe("research truthfulness",()=>{
  it("shows missing credentials and never fabricates a report",async()=>{
    status.mockResolvedValue({missing:["NEBIUS_API_KEY"],model:"",lab_available:false});start.mockResolvedValue(record);
    render(<ResearchPanel/>);fireEvent.click(screen.getByRole("button",{name:"Start research"}));
    await waitFor(()=>expect(screen.getByText(/Missing configuration:/)).toBeVisible());
    expect(screen.queryByText("Report",{exact:true})).toBeNull();
    expect(screen.queryByRole("button",{name:/Validate in isolated/})).toBeNull();
  });
  it("renders supporting quotations and clickable source IDs without turning source markup into HTML",async()=>{
    status.mockResolvedValue({missing:[],model:"fixture-model",lab_available:true});
    start.mockResolvedValue({...record,status:"completed",model:"fixture-model",sources:[{id:"S1",title:"<script>bad()</script>",url:"https://example.org/",retrieved_at:"2026-10-18",passage:"Deny access by default.",extracted:true}],report:{summary:"Assessment",claims:[{kind:"source_supported_fact",text:"Deny access by default.",source_id:"S1",quote:"Deny access by default.",support:"quote_matched_model_checked"}],scenario_id:"idor_basket_access",scenario_reason:"Two synthetic accounts",support_note:"Review evidence"}});
    render(<ResearchPanel/>);fireEvent.click(screen.getByRole("button",{name:"Start research"}));
    await waitFor(()=>expect(screen.getByRole("link",{name:"[S1]"})).toHaveAttribute("href","#research-S1"));
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getByRole("button",{name:/Validate in isolated/})).toBeEnabled();
    expect(lab).not.toHaveBeenCalled();
  });
});
