package bruecke

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	ClientIDs []string  `json:"client_ids,omitempty"`
	GroupIDs  []string  `json:"group_ids,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type GroupView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	ClientIDs []string  `json:"client_ids,omitempty"`
	GroupIDs  []string  `json:"group_ids,omitempty"`
	BuiltIn   bool      `json:"built_in"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

func (s *Store) Groups(domains []Domain) []GroupView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.groupViewsLocked(domains)
}

func (s *Store) NormalizeAssignmentReferences(clientIDs, groupIDs []string) ([]string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalizedClients := make([]string, 0, len(clientIDs))
	for _, id := range normalizeIDs(clientIDs) {
		resolved := s.resolveClientIDLocked(id)
		if _, ok := s.state.Clients[resolved]; !ok {
			return nil, nil, fmt.Errorf("unknown client %s", id)
		}
		normalizedClients = append(normalizedClients, resolved)
	}
	normalizedClients = normalizeIDs(normalizedClients)

	normalizedGroups := normalizeIDs(groupIDs)
	for _, id := range normalizedGroups {
		if !s.groupIDExistsLocked(id, true) {
			return nil, nil, fmt.Errorf("unknown group %s", id)
		}
	}
	return normalizedClients, normalizedGroups, nil
}

func (s *Store) AddGroup(name string, now time.Time) (GroupView, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return GroupView{}, fmt.Errorf("name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randomID("custom")
	group := Group{ID: id, Name: name, Type: "custom", CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	s.state.Groups[id] = group
	if err := s.saveLocked(); err != nil {
		delete(s.state.Groups, id)
		return GroupView{}, err
	}
	return groupView(group, false), nil
}

func (s *Store) UpdateGroup(id string, name *string, clientIDs, groupIDs *[]string) (GroupView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.state.Groups[id]
	if !ok || group.Type != "custom" {
		return GroupView{}, ErrGroupNotFound
	}
	previous := group
	if name != nil {
		trimmed := strings.TrimSpace(*name)
		if trimmed == "" {
			return GroupView{}, fmt.Errorf("name is required")
		}
		group.Name = trimmed
	}
	if clientIDs != nil {
		ids := normalizeIDs(*clientIDs)
		for _, clientID := range ids {
			if _, ok := s.state.Clients[clientID]; !ok {
				return GroupView{}, fmt.Errorf("unknown client %s", clientID)
			}
		}
		group.ClientIDs = ids
	}
	if groupIDs != nil {
		ids := normalizeIDs(*groupIDs)
		for _, childID := range ids {
			if childID == AllGroupID || childID == id || !s.groupIDExistsLocked(childID, false) {
				return GroupView{}, fmt.Errorf("invalid child group %s", childID)
			}
		}
		group.GroupIDs = ids
	}
	group.UpdatedAt = time.Now().UTC()
	s.state.Groups[id] = group
	if s.groupHasChildLocked(id, id, map[string]bool{}) {
		s.state.Groups[id] = previous
		return GroupView{}, fmt.Errorf("recursive group relationship")
	}
	if err := s.saveLocked(); err != nil {
		s.state.Groups[id] = previous
		return GroupView{}, err
	}
	return groupView(group, false), nil
}

func (s *Store) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.state.Groups[id]
	if !ok || group.Type != "custom" {
		return ErrGroupNotFound
	}
	previousGroups := map[string]Group{id: group}
	delete(s.state.Groups, id)
	for gid, item := range s.state.Groups {
		if !containsID(item.GroupIDs, id) {
			continue
		}
		previousGroups[gid] = item
		item.GroupIDs = removeID(item.GroupIDs, id)
		s.state.Groups[gid] = item
	}
	if err := s.saveLocked(); err != nil {
		for gid, previous := range previousGroups {
			s.state.Groups[gid] = previous
		}
		return err
	}
	return nil
}

func (s *Store) groupViewsLocked(domains []Domain) []GroupView {
	clientIDs := make([]string, 0, len(s.state.Clients))
	clientsByDomain := map[string][]string{}
	for id, client := range s.state.Clients {
		clientIDs = append(clientIDs, id)
		clientsByDomain[client.DomainID] = append(clientsByDomain[client.DomainID], id)
	}
	sort.Strings(clientIDs)
	allGroupIDs := make([]string, 0, len(domains)+len(s.state.Groups))
	for _, domain := range domains {
		allGroupIDs = append(allGroupIDs, domainGroupID(domain.ID))
	}
	for id, group := range s.state.Groups {
		if group.Type == "custom" {
			allGroupIDs = append(allGroupIDs, id)
		}
	}
	sort.Strings(allGroupIDs)
	views := []GroupView{{ID: AllGroupID, Name: "All", Type: "system", ClientIDs: clientIDs, GroupIDs: allGroupIDs, BuiltIn: true}}
	for _, domain := range domains {
		members := append([]string(nil), clientsByDomain[domain.ID]...)
		sort.Strings(members)
		views = append(views, GroupView{ID: domainGroupID(domain.ID), Name: domain.Name, Type: "domain", ClientIDs: members, BuiltIn: true})
	}
	custom := make([]Group, 0, len(s.state.Groups))
	for _, group := range s.state.Groups {
		if group.Type == "custom" {
			custom = append(custom, group)
		}
	}
	sort.Slice(custom, func(i, j int) bool { return custom[i].Name < custom[j].Name })
	for _, group := range custom {
		views = append(views, groupView(group, false))
	}
	return views
}

func groupView(group Group, builtIn bool) GroupView {
	return GroupView{
		ID:        group.ID,
		Name:      group.Name,
		Type:      group.Type,
		ClientIDs: append([]string(nil), group.ClientIDs...),
		GroupIDs:  append([]string(nil), group.GroupIDs...),
		BuiltIn:   builtIn,
		CreatedAt: group.CreatedAt,
		UpdatedAt: group.UpdatedAt,
	}
}

func (s *Store) clientGroupIDsLocked(clientIDValue, domainID string) []string {
	groups := map[string]struct{}{AllGroupID: {}}
	if domainID != "" {
		groups[domainGroupID(domainID)] = struct{}{}
	}
	changed := true
	for changed {
		changed = false
		for _, group := range s.state.Groups {
			if _, ok := groups[group.ID]; ok {
				continue
			}
			if containsID(group.ClientIDs, clientIDValue) || intersectsIDs(group.GroupIDs, groups) {
				groups[group.ID] = struct{}{}
				changed = true
			}
		}
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Store) groupHasChildLocked(groupID, targetID string, seen map[string]bool) bool {
	if seen[groupID] {
		return false
	}
	seen[groupID] = true
	group, ok := s.state.Groups[groupID]
	if !ok {
		return false
	}
	for _, childID := range group.GroupIDs {
		if childID == targetID {
			return true
		}
		if isCustomGroupID(childID) && s.groupHasChildLocked(childID, targetID, seen) {
			return true
		}
	}
	return false
}

func (s *Store) groupIDExistsLocked(id string, allowAll bool) bool {
	if id == AllGroupID {
		return allowAll
	}
	if isDomainGroupID(id) {
		return strings.TrimPrefix(id, "domain:") != ""
	}
	if isCustomGroupID(id) {
		group, ok := s.state.Groups[id]
		return ok && group.Type == "custom"
	}
	return false
}

func domainGroupID(domainID string) string {
	return "domain:" + domainID
}

func customGroupID(id string) string {
	if strings.HasPrefix(id, "custom:") {
		return id
	}
	return "custom:" + id
}

func isCustomGroupID(id string) bool {
	return strings.HasPrefix(id, "custom:")
}

func isDomainGroupID(id string) bool {
	return strings.HasPrefix(id, "domain:")
}
