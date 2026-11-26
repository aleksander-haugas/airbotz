#include "address_manager.h"
#include "pf.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

static int
has_permanent(const struct address_manager *m, const char *ip)
{
    size_t i;
    for (i = 0; i < m->permanent_count; i++)
        if (strcmp(m->permanent[i], ip) == 0)
            return 1;
    return 0;
}

static size_t
find_temporary(const struct address_manager *m, const char *ip)
{
    size_t i;
    for (i = 0; i < m->temporary_count; i++)
        if (strcmp(m->temporary[i].ip, ip) == 0)
            return i;
    return m->temporary_count;
}

int
address_manager_init(struct address_manager *m,
                     const struct address_manager_ops *ops, int pf_enabled)
{
    if (!m || (pf_enabled && (!ops || !ops->temp_add || !ops->temp_delete ||
                              !ops->perm_add || !ops->perm_delete)))
        return -1;
    memset(m, 0, sizeof(*m));
    if (ops)
        m->ops = *ops;
    m->pf_enabled = !!pf_enabled;
    if (storage_load_permanent(m->permanent, STORAGE_MAX_ENTRIES,
                               &m->permanent_count) != 0 ||
        storage_load_temporary(m->temporary, STORAGE_MAX_ENTRIES,
                               &m->temporary_count) != 0)
        return -1;
    return 0;
}

int
address_manager_restore(struct address_manager *m)
{
    struct storage_temporary valid[STORAGE_MAX_ENTRIES];
    size_t i, count = 0;
    time_t now;
    int changed = 0;

    if (!m || (now = time(NULL)) == (time_t)-1) return -1;
    for (i = 0; i < m->temporary_count; i++) {
        if (m->temporary[i].expires_at <= now) {
            if (m->pf_enabled && m->ops.temp_delete(m->temporary[i].ip) != 0) {
                size_t j;
                for (j = 0; j < i; j++)
                    if (m->temporary[j].expires_at <= now &&
                        m->ops.temp_add(m->temporary[j].ip) != 0)
                        return -2;
                return -1;
            }
            changed = 1;
        } else {
            valid[count++] = m->temporary[i];
        }
    }
    if (changed) {
        {
            int save_rc = storage_save_temporary(valid, count);
            if (save_rc == -1) {
                if (m->pf_enabled)
                    for (i = 0; i < m->temporary_count; i++)
                        if (m->temporary[i].expires_at <= now &&
                            m->ops.temp_add(m->temporary[i].ip) != 0)
                            return -2;
                return -1;
            }
            memcpy(m->temporary, valid, count * sizeof(valid[0]));
            m->temporary_count = count;
            if (save_rc == -2) return -3;
        }
    }

    if (m->pf_enabled) {
        for (i = 0; i < m->permanent_count; i++)
            if (m->ops.perm_add(m->permanent[i]) != 0)
                return -1;
        for (i = 0; i < m->temporary_count; i++)
            if (m->ops.temp_add(m->temporary[i].ip) != 0)
                return -1;
    }
    return 0;
}

int
address_manager_add_permanent(struct address_manager *m, const char *ip)
{
    char candidate[STORAGE_MAX_ENTRIES][STORAGE_IP_LEN];
    size_t count;
    int added_pf = 0;

    if (!m || !pf_valid_address(ip)) return -1;
    if (has_permanent(m, ip)) return 0;
    if (m->permanent_count >= STORAGE_MAX_ENTRIES) return -1;

    count = m->permanent_count;
    memcpy(candidate, m->permanent, count * sizeof(candidate[0]));
    (void)snprintf(candidate[count], sizeof(candidate[count]), "%s", ip);

    if (m->pf_enabled) {
        if (m->ops.perm_add(ip) != 0) return -1;
        added_pf = 1;
    }
    {
        int save_rc = storage_save_permanent((const char (*)[STORAGE_IP_LEN])candidate,
                                             count + 1);
        if (save_rc == -1) {
            if (added_pf && m->ops.perm_delete(ip) != 0) return -2;
            return -1;
        }
        memcpy(m->permanent, candidate, (count + 1) * sizeof(candidate[0]));
        m->permanent_count++;
        if (save_rc == -2) return -3;
    }
    return 0;
}

int
address_manager_delete_permanent(struct address_manager *m, const char *ip)
{
    char candidate[STORAGE_MAX_ENTRIES][STORAGE_IP_LEN];
    size_t i, j, count;
    int removed_pf = 0;

    if (!m || !pf_valid_address(ip)) return -1;
    for (i = 0; i < m->permanent_count; i++)
        if (strcmp(m->permanent[i], ip) == 0) break;
    if (i == m->permanent_count) return 0;

    count = m->permanent_count - 1;
    for (j = 0; j < i; j++) memcpy(candidate[j], m->permanent[j], STORAGE_IP_LEN);
    for (j = i; j < count; j++) memcpy(candidate[j], m->permanent[j + 1], STORAGE_IP_LEN);

    if (m->pf_enabled) {
        if (m->ops.perm_delete(ip) != 0) return -1;
        removed_pf = 1;
    }
    {
        int save_rc = storage_save_permanent((const char (*)[STORAGE_IP_LEN])candidate, count);
        if (save_rc == -1) {
            if (removed_pf && m->ops.perm_add(ip) != 0) return -2;
            return -1;
        }
        memcpy(m->permanent, candidate, count * sizeof(candidate[0]));
        m->permanent_count = count;
        if (save_rc == -2) return -3;
    }
    return 0;
}

int
address_manager_add_temporary(struct address_manager *m, const char *ip,
                              time_t expires_at)
{
    struct storage_temporary candidate[STORAGE_MAX_ENTRIES];
    size_t index, count;
    int is_new, added_pf = 0;

    if (!m || !pf_valid_address(ip) || expires_at <= time(NULL)) return -1;
    index = find_temporary(m, ip);
    is_new = index == m->temporary_count;
    if (is_new && m->temporary_count >= STORAGE_MAX_ENTRIES) return -1;

    count = m->temporary_count;
    memcpy(candidate, m->temporary, count * sizeof(candidate[0]));
    if (is_new) {
        index = count++;
        (void)snprintf(candidate[index].ip, sizeof(candidate[index].ip), "%s", ip);
    }
    candidate[index].expires_at = expires_at;

    if (m->pf_enabled) {
        if (m->ops.temp_add(ip) != 0) return -1;
        added_pf = is_new;
    }
    {
        int save_rc = storage_save_temporary(candidate, count);
        if (save_rc == -1) {
            if (added_pf && m->ops.temp_delete(ip) != 0) return -2;
            return -1;
        }
        memcpy(m->temporary, candidate, count * sizeof(candidate[0]));
        m->temporary_count = count;
        if (save_rc == -2) return -3;
    }
    return 0;
}

int
address_manager_delete_temporary(struct address_manager *m, const char *ip)
{
    struct storage_temporary candidate[STORAGE_MAX_ENTRIES];
    size_t index, count;

    if (!m || !pf_valid_address(ip)) return -1;
    index = find_temporary(m, ip);
    if (index == m->temporary_count) return 0;

    count = m->temporary_count - 1;
    memcpy(candidate, m->temporary, index * sizeof(candidate[0]));
    memcpy(&candidate[index], &m->temporary[index + 1],
           (count - index) * sizeof(candidate[0]));

    if (m->pf_enabled && m->ops.temp_delete(ip) != 0) return -1;
    {
        int save_rc = storage_save_temporary(candidate, count);
        if (save_rc == -1) {
            if (m->pf_enabled && m->ops.temp_add(ip) != 0) return -2;
            return -1;
        }
        memcpy(m->temporary, candidate, count * sizeof(candidate[0]));
        m->temporary_count = count;
        if (save_rc == -2) return -3;
    }
    return 0;
}

int
address_manager_expire(struct address_manager *m, time_t now, size_t *expired_count)
{
    struct storage_temporary candidate[STORAGE_MAX_ENTRIES];
    size_t i, count = 0, expired = 0;

    if (!m || now == (time_t)-1) return -1;
    for (i = 0; i < m->temporary_count; i++) {
        if (m->temporary[i].expires_at <= now) {
            if (m->pf_enabled && m->ops.temp_delete(m->temporary[i].ip) != 0) {
                size_t j;
                for (j = 0; j < i; j++)
                    if (m->temporary[j].expires_at <= now &&
                        m->ops.temp_add(m->temporary[j].ip) != 0)
                        return -2;
                return -1;
            }
            expired++;
        } else {
            candidate[count++] = m->temporary[i];
        }
    }
    if (!expired) {
        if (expired_count) *expired_count = 0;
        return 0;
    }
    {
        int save_rc = storage_save_temporary(candidate, count);
        if (save_rc == -1) {
            if (m->pf_enabled)
                for (i = 0; i < m->temporary_count; i++)
                    if (m->temporary[i].expires_at <= now &&
                        m->ops.temp_add(m->temporary[i].ip) != 0)
                        return -2;
            return -1;
        }
        memcpy(m->temporary, candidate, count * sizeof(candidate[0]));
        m->temporary_count = count;
        if (expired_count) *expired_count = expired;
        if (save_rc == -2) return -3;
    }
    if (expired_count) *expired_count = expired;
    return 0;
}
