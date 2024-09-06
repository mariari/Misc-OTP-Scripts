-module(raw).

-behaviour(wx_object).

-export([start/1, init/1, start_link/4]).

-include_lib("wx/include/wx.hrl").

-record(state, {field = 4 :: integer()}).


%% Need to replace wx:null() with a meaningful empty parent
start(Object) ->
    wx_object:start_link(?MODULE, {wx:null(), self(), Object, []}, []).

start_link(Notebook, Parent, Object, Config) ->
    wx_object:start_link(?MODULE, {Notebook, Parent, Object, Config}, []).


init(Initial) ->
    wx:batch(fun() -> do_init(Initial) end).


do_init({Notebook, Parent, Object, Config}) ->
    _Page = dummy_page(Notebook, "First Version of Raw"),
    Page = tree(Notebook, Object),
    {Page, #state{field = 1}}.




%% Tree version, lacks the ability to place objects, only text. Kind
%% of a sad limitation.

%% We could maybe make it work as we want
%% variable       | Item
%% v Tiles           Ordered Collection ...
%%   > { } array     an Array [4 items](1...)

%% Meaning we can maybe hack this to display an index/variable name
%% then the Object's printer method in the same frame

tree(Notebook, Object) ->
    Panel    = wxPanel:new(Notebook, []),
    Columned = wxTreeCtrl:new(Panel, []),
    RootName = lists:flatten(io_lib:format("Root: ~p",[Object])),
    RootID   = wxTreeCtrl:addRoot(Columned, RootName),

    raw(Object, Columned, RootID),

    wxTreeCtrl:expand(Columned, RootID),

    %% Setup sizers
    MainSizer = wxBoxSizer:new(?wxVERTICAL),
    Sizer = wxStaticBoxSizer:new(?wxVERTICAL, Panel,
				 [{label, "wxTreeCtrl"}]),


    Options = [{flag, ?wxEXPAND}, {proportion, 1}],
    wxSizer:add(Sizer, Columned, Options),
    wxSizer:add(MainSizer, Sizer, Options),
    wxPanel:setSizer(Panel, MainSizer),

    Panel.

%% First Dummy page, fairly useless
dummy_page(Notebook, Text) ->
    Win1 = wxPanel:new(Notebook, []),
    Win1Text = wxStaticText:new(Win1, ?wxID_ANY, Text),

    Sizer1 = wxBoxSizer:new(?wxHORIZONTAL),
    wxSizer:add(Sizer1, Win1Text),
    wxPanel:setSizer(Win1, Sizer1),

    wxStaticText:setForegroundColour(Win1Text, ?wxBLACK),
    Win1.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% raw item rendering
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%



-spec raw(Object, Tree, ID) -> ID when
      ID :: integer(),
      Object :: any(),
      Tree :: wxTreeCtrl:wxTreeCtrl().

raw(Object, Columned, RootID) when is_tuple(Object) ->
    raw(tuple_to_list(Object), Columned, RootID);

raw(Object, Columned, RootID) when is_list(Object) ->
    Id = wxTreeCtrl:appendItem(Columned, RootID, basicToString(Object), [{data, Object}]),

    Indexs  = lists:seq(1, length(Object)),
    raw_kv(lists:zip(Indexs, Object), Columned, Id),
    Id;


raw(Object, Columned, RootID) when is_map(Object) ->
    Id = wxTreeCtrl:appendItem(Columned, RootID, basicToString(Object), [{data, Object}]),

    raw_kv(maps:to_list(Object), Columned, Id),
    Id;

raw(Object, Columned, RootID) ->
    wxTreeCtrl:appendItem(Columned, RootID, basicToString(Object), [{data, Object}]).


raw_kv(PropertyList, Columned, RootID) ->
    wx:map(
      fun({Key, Value}) ->
              % We have this item, we should try raw on the value
              Message = lists:flatten(io_lib:format("~p: ~p",[Key, Value])),
              ItemID = raw(Value, Columned, RootID),
              wxTreeCtrl:setItemText(Columned, ItemID, Message)
      end,
      PropertyList).


basicToString(Object) ->
    lists:flatten(io_lib:format("~p",[Object])).
