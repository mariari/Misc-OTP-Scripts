-module(inspector).

-behaviour(wx_object).

-export([start_link/2, init/1]).

-include_lib("wx/include/wx.hrl").

-record(state, {field = 4 :: integer()}).


start_link(Object, Config) ->
    wx_object:start_link(?MODULE, {Object, Config}, []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init({Object, Config}) ->
    wx:batch(fun() -> do_init(Object, Config) end).

do_init(Object, Config) ->
    wx:new(),
    %% Make generic on embedding from the Config, the demo shows a
    %% good example of this.
    Frame = wxFrame:new(wx:null(), ?wxID_ANY, "Inspector", [{size, {1400, 800}}]),
    wxFrame:show(Frame),

    %% Should we include this panel?
    Panel    = wxPanel:new(Frame, []),
    Notebook = wxNotebook:new(Panel, 1, [{style, ?wxBK_DEFAULT}]),

    RawView = raw:start_link(Notebook, self(), Object, Config),
    wxNotebook:addPage(Notebook, RawView, "Raw"),


    %% Imagine these views were real
    DummyPage = dummy_page(Notebook, "First Page"),
    wxNotebook:addPage(Notebook, DummyPage, "Dummy Page Lets go", []),

    DummyPage2 = dummy_page(Notebook, "Demo 2"),
    wxNotebook:addPage(Notebook, DummyPage2, "Dummy Page 2", []),

    %% wxNotebook:connect(Notebook, command_notebook_page_changed,
    %%     	       [{skip, true}]), % {skip, true} has to be set on windows


    MainSizer = wxStaticBoxSizer:new(?wxVERTICAL, Panel,
        			     [{label, "Inspector"}]),
    wxPanel:setSizer(Panel, MainSizer),
    wxSizer:add(MainSizer, Notebook, [{proportion, 1}, {flag, ?wxEXPAND}]),

    {Frame, #state{field = 5}}.

%% We will use a dummy page and a real page at some page
dummy_page(Notebook, Text) ->
    Win1 = wxPanel:new(Notebook, []),
    Win1Text = wxStaticText:new(Win1, ?wxID_ANY, Text),

    Sizer1 = wxBoxSizer:new(?wxHORIZONTAL),
    wxSizer:add(Sizer1, Win1Text),
    wxPanel:setSizer(Win1, Sizer1),

    wxStaticText:setForegroundColour(Win1Text, ?wxBLACK),
    Win1.
